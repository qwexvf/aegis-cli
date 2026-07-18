//! A small semver engine — version parsing + precedence ordering.
//!
//! Shared by the capability [`allowlist`](crate::allowlist) (range matching)
//! and [`fix`](crate::fix) (upgrade-target ordering). Deliberately
//! dependency-free, standing in for Go's `Masterminds/semver`. Handles the
//! npm/node range dialect the ecosystems use — the constraint layer
//! (`^`/`~`/x-ranges/`||`) lives in `allowlist`; this module owns the
//! [`Version`] type, its parse, and semver §11 precedence (including
//! pre-release ordering).

use std::cmp::Ordering;

/// A pre-release identifier: numeric or alphanumeric, ordered per semver §11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreId {
    Num(u64),
    Text(String),
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreId::Num(a), PreId::Num(b)) => a.cmp(b),
            (PreId::Text(a), PreId::Text(b)) => a.cmp(b),
            // numeric identifiers always compare lower than alphanumeric ones.
            (PreId::Num(_), PreId::Text(_)) => Ordering::Less,
            (PreId::Text(_), PreId::Num(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed semantic version. Build metadata is discarded (ignored in
/// precedence, per semver §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    pub(crate) major: u64,
    pub(crate) minor: u64,
    pub(crate) patch: u64,
    pub(crate) pre: Vec<PreId>,
}

impl Version {
    pub(crate) fn new(major: u64, minor: u64, patch: u64) -> Version {
        Version {
            major,
            minor,
            patch,
            pre: Vec::new(),
        }
    }

    /// Parse a concrete version string ("v1.2.3", "4.17.21", "0.0.1-rc.1").
    /// Missing minor/patch default to 0. Returns `None` on malformed input —
    /// callers treat that as "no match", never an error.
    pub(crate) fn parse(s: &str) -> Option<Version> {
        let (comps, pre) = parse_components(s).ok()?;
        Some(Version {
            major: comps.first().copied().flatten().unwrap_or(0),
            minor: comps.get(1).copied().flatten().unwrap_or(0),
            patch: comps.get(2).copied().flatten().unwrap_or(0),
            pre,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| cmp_pre(&self.pre, &other.pre))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Pre-release ordering: a version with a pre-release is *lower* than the same
/// core version without one; two pre-releases compare identifier-by-identifier.
fn cmp_pre(a: &[PreId], b: &[PreId]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in a.iter().zip(b.iter()) {
                let o = x.cmp(y);
                if o != Ordering::Equal {
                    return o;
                }
            }
            a.len().cmp(&b.len())
        }
    }
}

/// Split a version core into up to three segments (`Some(n)` numeric, `None`
/// wildcard) plus its pre-release identifiers. Strips a leading `v`/`V` and any
/// `+build` metadata. Errors on non-numeric segments or the wrong shape.
pub(crate) type Components = (Vec<Option<u64>>, Vec<PreId>);

pub(crate) fn parse_components(s: &str) -> Result<Components, String> {
    let s = s.trim();
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    // drop +build metadata.
    let s = s.split('+').next().unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, parse_pre(p)),
        None => (s, Vec::new()),
    };
    if core.is_empty() {
        return Err("empty version".to_string());
    }
    let mut comps = Vec::new();
    for part in core.split('.') {
        if part == "*" || part == "x" || part == "X" {
            comps.push(None);
        } else if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) {
            let n = part
                .parse::<u64>()
                .map_err(|_| format!("version segment out of range: {part:?}"))?;
            comps.push(Some(n));
        } else {
            return Err(format!("invalid version segment: {part:?}"));
        }
    }
    if comps.is_empty() || comps.len() > 3 {
        return Err(format!("version has {} segments (want 1-3)", comps.len()));
    }
    Ok((comps, pre))
}

fn parse_pre(p: &str) -> Vec<PreId> {
    p.split('.')
        .map(|id| {
            if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
                match id.parse::<u64>() {
                    Ok(n) => PreId::Num(n),
                    Err(_) => PreId::Text(id.to_string()),
                }
            } else {
                PreId::Text(id.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_core_and_prerelease() {
        assert!(Version::parse("1.2.3-rc.1") < Version::parse("1.2.3"));
        assert!(Version::parse("1.2.10") > Version::parse("1.2.9"));
        assert!(Version::parse("2.0.0") > Version::parse("1.99.99"));
        assert_eq!(Version::parse("v1.0.0"), Version::parse("1.0.0"));
        // pre-release identifier precedence (§11): alpha < beta < numeric<text
        assert!(Version::parse("1.0.0-alpha") < Version::parse("1.0.0-beta"));
        assert!(Version::parse("1.0.0-1") < Version::parse("1.0.0-alpha"));
        assert!(Version::parse("1.0.0-alpha.1") < Version::parse("1.0.0-alpha.2"));
    }

    #[test]
    fn bad_input_is_none() {
        assert!(Version::parse("not-a-version").is_none());
        assert!(Version::parse("").is_none());
    }
}
