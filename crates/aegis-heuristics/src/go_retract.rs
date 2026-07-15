//! Go module retract detector. Port of the `retract` parsing in
//! `parser_go.go` + `check_go_retract.go`.
//!
//! Flags [`Capability::VersionUnpublished`] when the installed version of a
//! Go module appears in that module's own `retract` list or range — the
//! author's explicit statement that the version is unsafe.

use std::sync::OnceLock;

use aegis_domain::Capability;
use regex::Regex;

use crate::{NormalizedPackage, RetractRange};

// `retract v1.0.0` / `retract v1.0.0 // reason`
fn version_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?m)^\s*retract\s+(v[\w.+-]+)").unwrap())
}
// `retract [v1.0.0, v1.1.0]`
fn range_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?m)^\s*retract\s+\[\s*(v[\w.+-]+)\s*,\s*(v[\w.+-]+)\s*\]").unwrap()
    })
}
// inner body of a block-form `retract ( … )`
fn block_body_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?ms)^\s*retract\s*\(([^)]+)\)").unwrap())
}
// bare version token on a line inside a block
fn block_version_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?m)^\s*(v[\w.+-]+)").unwrap())
}
// range token inside a block body
fn block_range_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?m)^\s*\[\s*(v[\w.+-]+)\s*,\s*(v[\w.+-]+)\s*\]").unwrap())
}

/// Parse every `retract` directive (single, range, and block forms) out of a
/// go.mod body. Returns exact versions and inclusive ranges.
pub fn parse_go_retract(body: &str) -> (Vec<String>, Vec<RetractRange>) {
    let mut versions = Vec::new();
    let mut ranges = Vec::new();

    // Single-line `retract vX` (the version pattern won't match `retract [`
    // or `retract (`, so no overlap with the range/block forms).
    for caps in version_pattern().captures_iter(body) {
        versions.push(caps[1].to_string());
    }
    for caps in range_pattern().captures_iter(body) {
        ranges.push(RetractRange {
            low: caps[1].to_string(),
            high: caps[2].to_string(),
        });
    }

    // Block-form `retract ( … )`.
    for block in block_body_pattern().captures_iter(body) {
        let block_body = &block[1];
        // Extract ranges first, then blank them out so their version tokens
        // don't get re-picked by the single-version pass.
        for m in block_range_pattern().captures_iter(block_body) {
            ranges.push(RetractRange {
                low: m[1].to_string(),
                high: m[2].to_string(),
            });
        }
        let cleaned = block_range_pattern().replace_all(block_body, "");
        for m in block_version_pattern().captures_iter(&cleaned) {
            // Skip comment-only lines that happen to start with a v-like token.
            if m[0].trim_start().starts_with("//") {
                continue;
            }
            versions.push(m[1].to_string());
        }
    }

    (versions, ranges)
}

/// Parse a go module version ("v1.2.3") into a comparable [`semver::Version`],
/// stripping the leading `v`. Prerelease/build metadata carry through.
fn parse_go_version(v: &str) -> Option<semver::Version> {
    semver::Version::parse(v.strip_prefix('v').unwrap_or(v)).ok()
}

/// Fires when `pkg.version` is in the module's own retract list or range.
/// No-op when the version is empty or unparseable — better silent than noisy.
pub fn check_go_retract(pkg: &NormalizedPackage) -> Vec<Capability> {
    if pkg.version.is_empty() {
        return Vec::new();
    }
    if pkg.retracted_versions.iter().any(|v| v == &pkg.version) {
        return vec![Capability::VersionUnpublished];
    }
    if pkg.retracted_ranges.is_empty() {
        return Vec::new();
    }
    let Some(v) = parse_go_version(&pkg.version) else {
        return Vec::new();
    };
    for r in &pkg.retracted_ranges {
        let (Some(low), Some(high)) = (parse_go_version(&r.low), parse_go_version(&r.high)) else {
            continue;
        };
        if v >= low && v <= high {
            return vec![Capability::VersionUnpublished];
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_domain::Ecosystem;

    fn pkg_from(gomod: &str, version: &str) -> NormalizedPackage {
        let (versions, ranges) = parse_go_retract(gomod);
        let mut p = NormalizedPackage::new("example.com/mymod", Ecosystem::Go);
        p.version = version.to_string();
        p.retracted_versions = versions;
        p.retracted_ranges = ranges;
        p
    }

    #[test]
    fn single_retracted_version_fires() {
        let gomod = "module example.com/mymod\ngo 1.22\nretract v1.0.0 // security vulnerability\n";
        assert_eq!(
            check_go_retract(&pkg_from(gomod, "v1.0.0")),
            vec![Capability::VersionUnpublished]
        );
    }

    #[test]
    fn non_retracted_version_does_not_fire() {
        let gomod = "module example.com/mymod\ngo 1.22\nretract v1.0.0\n";
        assert!(check_go_retract(&pkg_from(gomod, "v1.1.0")).is_empty());
    }

    #[test]
    fn empty_version_no_signal() {
        let mut p = NormalizedPackage::new("m", Ecosystem::Go);
        p.retracted_versions = vec!["v1.0.0".into()];
        assert!(check_go_retract(&p).is_empty());
    }

    #[test]
    fn range_fires_when_in_range() {
        let gomod = "module example.com/mymod\ngo 1.22\nretract [v1.0.0, v1.2.0] // affected\n";
        assert_eq!(
            check_go_retract(&pkg_from(gomod, "v1.1.0")),
            vec![Capability::VersionUnpublished]
        );
    }

    #[test]
    fn range_does_not_fire_above_range() {
        let gomod = "module example.com/mymod\ngo 1.22\nretract [v1.0.0, v1.2.0]\n";
        assert!(check_go_retract(&pkg_from(gomod, "v1.3.0")).is_empty());
    }

    #[test]
    fn block_form_single_versions() {
        let gomod = "module example.com/mymod\ngo 1.22\nretract (\n\tv1.0.0 // first bad\n\tv1.1.0 // second bad\n)\n";
        assert_eq!(
            check_go_retract(&pkg_from(gomod, "v1.1.0")),
            vec![Capability::VersionUnpublished]
        );
    }

    #[test]
    fn block_form_range() {
        let gomod = "module example.com/mymod\ngo 1.22\nretract (\n\t[v1.2.0, v1.4.0] // range in block\n)\n";
        assert_eq!(
            check_go_retract(&pkg_from(gomod, "v1.3.0")),
            vec![Capability::VersionUnpublished]
        );
        // and a version outside the block range does not fire
        assert!(check_go_retract(&pkg_from(gomod, "v1.5.0")).is_empty());
    }

    #[test]
    fn block_range_versions_not_double_counted_as_singles() {
        // the range bounds must not leak into retracted_versions
        let gomod = "module m\nretract (\n\t[v1.2.0, v1.4.0]\n)\n";
        let (versions, ranges) = parse_go_retract(gomod);
        assert!(versions.is_empty(), "got singles: {versions:?}");
        assert_eq!(ranges.len(), 1);
    }
}
