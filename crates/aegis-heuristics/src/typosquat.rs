//! Typosquat detector. Port of `typosquat.go` + `check_typosquat.go`.
//!
//! Flags [`Capability::TyposquatRisk`] when a package name is within
//! Levenshtein distance 2 of a top package in the same ecosystem but
//! isn't itself in that list. Top-package lists are embedded at build
//! time so the detector works fully offline.

use std::collections::HashSet;
use std::sync::OnceLock;

use aegis_domain::{Capability, Ecosystem};

use crate::NormalizedPackage;

// Curated top-package lists, embedded (mirrors the Go //go:embed).
const TOP_NPM: &str = include_str!("../data/top_npm_packages.txt");
const TOP_PYPI: &str = include_str!("../data/top_pypi_packages.txt");
const TOP_CRATES: &str = include_str!("../data/top_crates_packages.txt");
const TOP_CRAN: &str = include_str!("../data/top_cran_packages.txt");
const TOP_HACKAGE: &str = include_str!("../data/top_hackage_packages.txt");
const TOP_CPAN: &str = include_str!("../data/top_cpan_packages.txt");

/// Parse a newline-separated list, skipping blanks and `#` comments.
fn parse_top_list(raw: &str) -> HashSet<String> {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// The top-package set for an ecosystem, or None when unsupported
/// (unsupported ecosystems get no signal — better silent than a
/// false positive). Mirrors `topPackages`.
fn top_packages(eco: Ecosystem) -> Option<&'static HashSet<String>> {
    macro_rules! cached {
        ($name:ident, $raw:expr) => {{
            static C: OnceLock<HashSet<String>> = OnceLock::new();
            C.get_or_init(|| parse_top_list($raw))
        }};
    }
    Some(match eco {
        Ecosystem::Npm => cached!(NPM, TOP_NPM),
        Ecosystem::PyPI => cached!(PYPI, TOP_PYPI),
        Ecosystem::Crates => cached!(CRATES, TOP_CRATES),
        Ecosystem::Cran => cached!(CRAN, TOP_CRAN),
        Ecosystem::Hackage => cached!(HACKAGE, TOP_HACKAGE),
        Ecosystem::Cpan => cached!(CPAN, TOP_CPAN),
        _ => return None,
    })
}

/// Detect a typosquat. Mirrors `checkTyposquat`.
pub fn check_typosquat(pkg: &NormalizedPackage) -> Vec<Capability> {
    if pkg.name.is_empty() {
        return Vec::new();
    }
    let Some(eco) = pkg.ecosystem_name else {
        return Vec::new();
    };
    let Some(top) = top_packages(eco) else {
        return Vec::new();
    };

    // Scoped npm packages compare the bare name (@scope/name → name).
    let compare = pkg
        .name
        .strip_prefix('@')
        .and_then(|_| pkg.name.split_once('/').map(|(_, n)| n))
        .unwrap_or(&pkg.name);

    if top.contains(compare) {
        return Vec::new(); // it IS a top package, not a squat
    }
    for top_name in top {
        if levenshtein(compare, top_name) <= 2 {
            return vec![Capability::TyposquatRisk];
        }
    }
    Vec::new()
}

/// Classic DP edit distance. Mirrors `levenshtein`.
fn levenshtein(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, eco: Ecosystem) -> NormalizedPackage {
        NormalizedPackage::new(name, eco)
    }

    #[test]
    fn levenshtein_basics() {
        assert_eq!(levenshtein("lodash", "lodash"), 0);
        assert_eq!(levenshtein("lodash", "lodahs"), 2); // transposition = 2 subs
        assert_eq!(levenshtein("express", "expresss"), 1);
        assert_eq!(levenshtein("", "abc"), 3);
    }

    #[test]
    fn flags_near_miss_of_top_package() {
        // "lodahs" is distance-2 from "lodash" (a top npm package).
        assert_eq!(
            check_typosquat(&pkg("lodahs", Ecosystem::Npm)),
            vec![Capability::TyposquatRisk]
        );
        assert_eq!(
            check_typosquat(&pkg("expresss", Ecosystem::Npm)),
            vec![Capability::TyposquatRisk]
        );
    }

    #[test]
    fn real_top_package_is_not_flagged() {
        assert!(check_typosquat(&pkg("lodash", Ecosystem::Npm)).is_empty());
        assert!(check_typosquat(&pkg("express", Ecosystem::Npm)).is_empty());
    }

    #[test]
    fn scoped_name_compares_bare() {
        // @atk/lodash → "lodash" is a real package → not flagged.
        assert!(check_typosquat(&pkg("@atk/lodash", Ecosystem::Npm)).is_empty());
        // @atk/lodahs → "lodahs" is distance-2 → flagged.
        assert_eq!(
            check_typosquat(&pkg("@atk/lodahs", Ecosystem::Npm)),
            vec![Capability::TyposquatRisk]
        );
    }

    #[test]
    fn unsupported_ecosystem_no_signal() {
        assert!(check_typosquat(&pkg("anything", Ecosystem::Go)).is_empty());
    }

    #[test]
    fn distant_name_not_flagged() {
        assert!(check_typosquat(&pkg("my-totally-unique-app-name", Ecosystem::Npm)).is_empty());
    }
}
