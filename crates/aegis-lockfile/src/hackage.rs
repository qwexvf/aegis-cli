//! Haskell parsers. Port of `lockfile_hackage.go`. Two sources:
//! `cabal.project.freeze` (== pins, `any.` prefix stripped) and
//! `stack.yaml.lock` (hackage extra-deps). OSV "Hackage".

use std::collections::HashSet;
use std::sync::OnceLock;

use aegis_domain::{Dependency, Ecosystem};
use regex::Regex;

use crate::{DirectMap, LockfileParser, ParseError};

// --- cabal.project.freeze --------------------------------------------

pub struct CabalFreeze;

fn cabal_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\S+)\s+==(\S+?),?\s*$").unwrap())
}

impl LockfileParser for CabalFreeze {
    fn filename(&self) -> &'static str {
        "cabal.project.freeze"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Hackage
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        for line in text.lines() {
            // Strip "constraints:" prefix (first package may be inline).
            let line = line
                .trim()
                .strip_prefix("constraints:")
                .unwrap_or(line.trim());
            let Some(m) = cabal_entry_re().captures(line) else {
                continue;
            };
            // cabal qualifies with "any." — strip to recover the bare name.
            let name = m[1].strip_prefix("any.").unwrap_or(&m[1]).to_string();
            out.push(Dependency {
                ecosystem: Ecosystem::Hackage,
                name,
                version: m[2].to_string(),
                ..Default::default()
            });
        }
        Ok(out)
    }
}

// --- stack.yaml.lock -------------------------------------------------

pub struct StackYamlLock;

fn stack_hackage_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s+hackage:\s+(\S+)").unwrap())
}
fn hackage_name_ver_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(.*?)-(\d[^@]*)").unwrap())
}

impl LockfileParser for StackYamlLock {
    fn filename(&self) -> &'static str {
        "stack.yaml.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Hackage
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for line in text.lines() {
            let Some(m) = stack_hackage_re().captures(line) else {
                continue;
            };
            // "aeson-2.1.2.1@sha256:abc,size:12345" → strip @… suffix.
            let spec = m[1].split('@').next().unwrap_or("").to_string();
            if !seen.insert(spec.clone()) {
                continue;
            }
            let Some(nv) = hackage_name_ver_re().captures(&spec) else {
                continue;
            };
            out.push(Dependency {
                ecosystem: Ecosystem::Hackage,
                name: nv[1].to_string(),
                version: nv[2].to_string(),
                ..Default::default()
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cabal_strips_any_prefix_and_pins() {
        let raw = b"constraints: any.aeson ==2.1.2.1,\n\
                    \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20any.base ==4.17.2.0,\n\
                    \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20aeson -cffi,\n\
                    \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20any.bytestring ==0.11.5.3\n";
        let deps = CabalFreeze.parse(raw, &DirectMap::new()).unwrap();
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        // "aeson -cffi" has no == → skipped.
        assert_eq!(names, ["aeson", "base", "bytestring"]);
        assert_eq!(deps[0].version, "2.1.2.1");
    }

    #[test]
    fn stack_extracts_hackage_extra_deps() {
        let raw = b"packages:\n\
                    - completed:\n\
                    \x20\x20\x20\x20hackage: aeson-2.1.2.1@sha256:abc,size:12345\n\
                    \x20\x20original:\n\
                    \x20\x20\x20\x20hackage: aeson-2.1.2.1@sha256:abc,size:12345\n";
        let deps = StackYamlLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 1); // deduped
        assert_eq!(deps[0].name, "aeson");
        assert_eq!(deps[0].version, "2.1.2.1");
    }
}
