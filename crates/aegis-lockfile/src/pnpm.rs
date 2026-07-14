//! `pnpm-lock.yaml` parser. Port of `lockfile_pnpm.go`. npm ecosystem.
//!
//! Hand-parses the `packages:` section (no YAML dep): entries sit at
//! exactly 2-space indent and end in `:`. Keys come in modern (`@`
//! separator) and legacy (`/` separator) shapes.

use std::collections::HashSet;

use aegis_domain::{Dependency, Ecosystem};

use crate::{DirectMap, LockfileParser, ParseError};

pub struct PnpmLock;

impl LockfileParser for PnpmLock {
    fn filename(&self) -> &'static str {
        "pnpm-lock.yaml"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
    fn parse(&self, raw: &[u8], direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut deps = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut in_packages = false;

        for line in text.lines() {
            if !in_packages {
                if line == "packages:" {
                    in_packages = true;
                }
                continue;
            }
            // Another top-level key ends the section.
            if !line.starts_with(' ') && line.trim_end().ends_with(':') && line != "packages:" {
                break;
            }
            // Entry lines are at exactly 2-space indent.
            let indent = line.len() - line.trim_start_matches(' ').len();
            if indent != 2 {
                continue;
            }
            let trimmed = line.trim();
            if !trimmed.ends_with(':') {
                continue;
            }
            let mut entry = trimmed.trim_end_matches(':').trim_matches(['\'', '"']);
            entry = entry.strip_prefix('/').unwrap_or(entry);

            // Strip pnpm peer-dep suffix "name@1.2.3(react@18)" when balanced.
            if let Some(i) = entry.find('(') {
                if i > 0 && entry.ends_with(')') {
                    entry = &entry[..i];
                }
            }

            let Some((name, version)) = split_pnpm_entry(entry) else {
                continue;
            };
            let key = format!("{name}@{version}");
            if !seen.insert(key) {
                continue;
            }
            deps.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: version.to_string(),
                direct: direct.get(name).copied().unwrap_or(false),
                ..Default::default()
            });
        }
        Ok(deps)
    }
}

/// Split one packages key into (name, version). Modern (`@`) format
/// first, then legacy (`/`). Mirrors `splitPnpmEntry`.
fn split_pnpm_entry(entry: &str) -> Option<(&str, &str)> {
    if let Some(idx) = entry.rfind('@') {
        if idx > 0 {
            let name = &entry[..idx];
            let ver = &entry[idx + 1..];
            if !ver.is_empty() && !ver.contains('/') {
                return Some((name, ver));
            }
        }
    }
    if let Some(idx) = entry.rfind('/') {
        if idx > 0 {
            return Some((&entry[..idx], &entry[idx + 1..]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_and_legacy_entries() {
        let raw = b"lockfileVersion: '9.0'\n\
                    packages:\n\
                    \x20\x20'@babel/core@7.23.0':\n\
                    \x20\x20\x20\x20resolution: {integrity: sha512-x}\n\
                    \x20\x20lodash@4.17.21:\n\
                    \x20\x20\x20\x20resolution: {integrity: sha512-y}\n\
                    \x20\x20/react@18.2.0(peer@1.0.0):\n\
                    snapshots:\n";
        let deps = PnpmLock.parse(raw, &DirectMap::new()).unwrap();
        let mut names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["@babel/core", "lodash", "react"]);
        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert_eq!(react.version, "18.2.0"); // peer suffix stripped
    }
}
