//! Nim `nimble.lock` parser.
//!
//! `nimble lock` writes a JSON document with a top-level `packages` object
//! keyed by package name; each entry pins a `version` (plus vcs revision, url,
//! and checksums we don't need for a dependency inventory). The lockfile lists
//! the fully-resolved set with no direct/transitive marker, so every dep is
//! reported transitive (`direct = false`), matching the other lockfile-only
//! ecosystems.

use std::collections::HashMap;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct NimbleLock;

#[derive(Deserialize, Default)]
struct Entry {
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    packages: HashMap<String, Entry>,
}

impl LockfileParser for NimbleLock {
    fn filename(&self) -> &'static str {
        "nimble.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Nimble
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc =
            serde_json::from_slice(raw).map_err(|e| ParseError(format!("nimble.lock: {e}")))?;
        let mut out: Vec<Dependency> = doc
            .packages
            .into_iter()
            .filter(|(_, e)| !e.version.is_empty())
            .map(|(name, e)| Dependency {
                ecosystem: Ecosystem::Nimble,
                name,
                version: e.version,
                direct: false,
                ..Default::default()
            })
            .collect();
        // HashMap iteration order is nondeterministic; sort for stable output.
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packages_and_pins_versions() {
        let raw = br#"{
            "version": 1,
            "packages": {
                "nimcrypto": {
                    "version": "0.5.4",
                    "vcsRevision": "deadbeef",
                    "url": "https://github.com/cheatfate/nimcrypto",
                    "downloadMethod": "git",
                    "dependencies": [],
                    "checksums": { "sha1": "abc" }
                },
                "stew": {
                    "version": "0.1.0",
                    "downloadMethod": "git"
                }
            }
        }"#;
        let deps = NimbleLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        // sorted by name
        assert_eq!(deps[0].name, "nimcrypto");
        assert_eq!(deps[0].version, "0.5.4");
        assert_eq!(deps[0].ecosystem, Ecosystem::Nimble);
        assert!(!deps[0].direct);
        assert_eq!(deps[1].name, "stew");
        assert_eq!(deps[1].version, "0.1.0");
    }

    #[test]
    fn skips_versionless_entries_and_handles_empty() {
        let raw = br#"{"version":1,"packages":{"ghost":{"downloadMethod":"git"}}}"#;
        assert!(NimbleLock.parse(raw, &DirectMap::new()).unwrap().is_empty());
        let empty = br#"{"version":1,"packages":{}}"#;
        assert!(NimbleLock
            .parse(empty, &DirectMap::new())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn corrupt_json_errors() {
        assert!(NimbleLock.parse(b"not json", &DirectMap::new()).is_err());
    }
}
