//! Unlisted-large-file detector. Port of `unlisted_payload.go` +
//! `check_unlisted_payload.go`.
//!
//! Flags [`Capability::UnlistedLargeFile`] when a tarball ships a large
//! (≥512 KB) JS-family code file that is neither declared in the package's
//! `files` allowlist nor under a standard build-output directory. The
//! TanStack router_init.js worm payload (2.3 MB at root, not in `files`)
//! is the reference incident.

use aegis_domain::Capability;

use crate::manifest::extract_package_files_field;
use crate::NormalizedPackage;

/// Minimum file size (bytes) that triggers the check. 512 KB keeps
/// false-positives out of the way of packages that legitimately bundle a
/// large compiled output at root.
const SIZE_THRESHOLD: usize = 512_000;

/// Directory prefixes expected to hold compiled output not present upstream.
/// Files under these are whitelisted. Keep in sync with tarball-drift's
/// build-output dirs.
const BUILD_OUTPUT_PREFIXES: &[&str] = &[
    "dist/", "lib/", "build/", "out/", "cjs/", "mjs/", "esm/", "umd/", "types/", "typings/", "dts/",
];

/// Root-level files always expected in a tarball regardless of `files`.
const METADATA_FILES: &[&str] = &[
    "package.json",
    "readme.md",
    "readme",
    "license",
    "license.md",
    "license.txt",
    "changelog.md",
    "changelog",
    "notice",
    "authors",
    "contributors.md",
];

/// File extensions that could carry an executable payload. Intentionally
/// narrow (JS-family only) to keep the false-positive rate low.
fn is_unlisted_code_file(filename: &str) -> bool {
    let base = filename.rsplit_once('/').map_or(filename, |(_, b)| b);
    let ext = match base.rsplit_once('.') {
        Some((_, e)) => e.to_ascii_lowercase(),
        None => return false,
    };
    matches!(
        ext.as_str(),
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "cts" | "mts"
    )
}

/// A predicate accepting files expected in a published tarball: build-output
/// prefixes, metadata literals, and paths matching the `files` field.
struct Whitelist {
    literals: Vec<String>,
    prefixes: Vec<String>,
}

impl Whitelist {
    fn build(pkg_files: &[String]) -> Self {
        let mut prefixes: Vec<String> = BUILD_OUTPUT_PREFIXES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut literals: Vec<String> = METADATA_FILES.iter().map(|s| s.to_string()).collect();
        for p in pkg_files {
            let p = p.trim().trim_start_matches('/').trim_start_matches("./");
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            let lower = p.to_ascii_lowercase();
            literals.push(lower.clone());
            // Directory entries act as prefix whitelist.
            if !p.contains('.') || p.ends_with('/') {
                prefixes.push(format!("{}/", lower.trim_end_matches('/')));
            }
        }
        Whitelist { literals, prefixes }
    }

    fn accepts(&self, path: &str) -> bool {
        let lp = path.trim_start_matches("./").to_ascii_lowercase();
        if self.literals.iter().any(|l| l == &lp) {
            return true;
        }
        let base = lp.rsplit_once('/').map_or(lp.as_str(), |(_, b)| b);
        if self.literals.iter().any(|l| l == base) {
            return true;
        }
        self.prefixes.iter().any(|pref| lp.starts_with(pref))
    }
}

/// Fires when the tarball contains a large unlisted JS-family code file.
pub fn check_unlisted_payload(pkg: &NormalizedPackage) -> Vec<Capability> {
    if pkg.files.is_empty() {
        return Vec::new();
    }
    let pkg_files = extract_package_files_field(&pkg.manifest_raw);
    let whitelist = Whitelist::build(&pkg_files);
    for (filename, body) in &pkg.files {
        if body.len() < SIZE_THRESHOLD {
            continue;
        }
        if !is_unlisted_code_file(filename) {
            continue;
        }
        if whitelist.accepts(filename) {
            continue;
        }
        return vec![Capability::UnlistedLargeFile];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse_npm_manifest;
    use std::collections::HashMap;

    fn large_js(n: usize) -> Vec<u8> {
        let mut b = "var x = 1;\n".repeat(n / 11 + 1).into_bytes();
        b.truncate(n);
        b
    }

    fn pkg(manifest: &str, files: &[(&str, Vec<u8>)]) -> NormalizedPackage {
        let mut map = HashMap::new();
        for (n, b) in files {
            map.insert(n.to_string(), b.clone());
        }
        parse_npm_manifest("", manifest.as_bytes(), map)
    }

    #[test]
    fn tanstack_router_init_flagged() {
        // 2.3 MB router_init.js at root, not in files: ["dist"]
        let p = pkg(
            r#"{"name":"@tanstack/react-router","version":"1.169.5","files":["dist"]}"#,
            &[
                ("router_init.js", large_js(600_000)),
                ("dist/index.js", large_js(1_000)),
            ],
        );
        assert_eq!(
            check_unlisted_payload(&p),
            vec![Capability::UnlistedLargeFile]
        );
    }

    #[test]
    fn large_file_in_dist_whitelisted() {
        let p = pkg(
            r#"{"name":"pkg","version":"1.0.0"}"#,
            &[("dist/bundle.js", large_js(1_000_000))],
        );
        assert!(check_unlisted_payload(&p).is_empty());
    }

    #[test]
    fn large_file_declared_in_files_field() {
        let p = pkg(
            r#"{"name":"pkg","version":"1.0.0","files":["bundle.js"]}"#,
            &[("bundle.js", large_js(600_000))],
        );
        assert!(check_unlisted_payload(&p).is_empty());
    }

    #[test]
    fn large_non_code_file_not_flagged() {
        let p = pkg(
            r#"{"name":"pkg","version":"1.0.0"}"#,
            &[("big.woff2", large_js(600_000))],
        );
        assert!(check_unlisted_payload(&p).is_empty());
    }

    #[test]
    fn small_js_at_root_not_flagged() {
        let p = pkg(
            r#"{"name":"pkg","version":"1.0.0"}"#,
            &[("index.js", large_js(1_000))],
        );
        assert!(check_unlisted_payload(&p).is_empty());
    }

    #[test]
    fn empty_source_no_signal() {
        assert!(check_unlisted_payload(&NormalizedPackage::default()).is_empty());
    }
}
