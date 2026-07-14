//! Hardcoded-secret detector. Port of `check_secrets.go`.
//!
//! Fires [`Capability::HardcodedSecret`] when a source file contains a
//! structured credential (AWS/GitHub/npm/PEM/Stripe/SendGrid/Twilio/
//! Slack/Bearer). Vendor placeholder tokens are excluded so tutorial
//! snippets don't false-positive. No high-entropy generic detection —
//! its false-positive rate is unacceptable at scale.

use std::sync::OnceLock;

use aegis_domain::Capability;
use regex::bytes::RegexSet;

use crate::source::is_analyzable_source;
use crate::NormalizedPackage;

/// Per-file scan cap (256 KiB), matching the Go `scanCap`.
const SCAN_CAP: usize = 256 * 1024;

/// Vendor-published example tokens that must never trigger the detector.
const KNOWN_PLACEHOLDERS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "AKIA0000000000000000",
    "AKIAEXAMPLEAKIAEXAMPL",
    "ASIAIOSFODNN7EXAMPLE",
];

/// Individual patterns, kept separately so a match can be re-checked
/// against the placeholder list (a `RegexSet` reports which matched but
/// not the matched text, so we re-run the specific pattern).
fn secret_patterns() -> &'static [regex::bytes::Regex] {
    static PATS: OnceLock<Vec<regex::bytes::Regex>> = OnceLock::new();
    PATS.get_or_init(|| {
        [
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bASIA[0-9A-Z]{16}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
            r"\bnpm_[A-Za-z0-9]{36}\b",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            r"\bAC[0-9a-fA-F]{32}\b",
            r"\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b",
            r"(?i)\bBearer\s+[A-Za-z0-9+/\-_]{40,}={0,2}\b",
        ]
        .iter()
        .map(|p| regex::bytes::Regex::new(p).unwrap())
        .collect()
    })
}

/// A fast pre-filter: if none of the patterns match at all, skip the
/// per-pattern placeholder re-check.
fn secret_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| RegexSet::new(secret_patterns().iter().map(|r| r.as_str())).unwrap())
}

/// Scan a package's analyzable source files for a hardcoded credential.
pub fn check_secrets(pkg: &NormalizedPackage) -> Vec<Capability> {
    for (filename, body) in &pkg.files {
        if !is_analyzable_source(filename) {
            continue;
        }
        let slice = if body.len() > SCAN_CAP {
            &body[..SCAN_CAP]
        } else {
            &body[..]
        };
        if contains_hardcoded_secret(slice) {
            return vec![Capability::HardcodedSecret];
        }
    }
    Vec::new()
}

fn contains_hardcoded_secret(body: &[u8]) -> bool {
    if !secret_set().is_match(body) {
        return false;
    }
    for p in secret_patterns() {
        for m in p.find_iter(body) {
            if !is_known_placeholder(m.as_bytes()) {
                return true;
            }
        }
    }
    false
}

fn is_known_placeholder(m: &[u8]) -> bool {
    KNOWN_PLACEHOLDERS.iter().any(|p| p.as_bytes() == m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_domain::Ecosystem;

    fn pkg_with(file: &str, body: &str) -> NormalizedPackage {
        NormalizedPackage::new("x", Ecosystem::Npm).with_file(file, body.as_bytes().to_vec())
    }

    #[test]
    fn detects_aws_key() {
        let p = pkg_with("index.js", "const k = 'AKIAZ2XICEXAMPLE7QWE';");
        assert_eq!(check_secrets(&p), vec![Capability::HardcodedSecret]);
    }

    #[test]
    fn detects_github_and_pem() {
        let gh = pkg_with(
            "a.py",
            "token = 'ghp_0123456789abcdefghijABCDEFGHIJ0123456789'",
        );
        assert_eq!(check_secrets(&gh), vec![Capability::HardcodedSecret]);
        let pem = pkg_with("k.rs", "-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(check_secrets(&pem), vec![Capability::HardcodedSecret]);
    }

    #[test]
    fn ignores_aws_placeholder() {
        let p = pkg_with("readme.js", "example: AKIAIOSFODNN7EXAMPLE");
        assert!(check_secrets(&p).is_empty());
    }

    #[test]
    fn ignores_non_source_files() {
        // AWS key in a non-source file (e.g. .txt) is not scanned.
        let p = pkg_with("notes.txt", "AKIAZ2XICEXAMPLE7QWE");
        assert!(check_secrets(&p).is_empty());
    }

    #[test]
    fn clean_source_is_empty() {
        let p = pkg_with("index.js", "export const add = (a, b) => a + b;");
        assert!(check_secrets(&p).is_empty());
    }
}
