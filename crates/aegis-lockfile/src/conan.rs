//! Conan (C/C++) `conan.lock` parser.
//!
//! Conan 2.x lockfiles are JSON with `requires` / `build_requires` /
//! `python_requires` arrays of package references shaped like
//! `name/version#recipe-revision%timestamp`. We flatten all three arrays,
//! pulling the name (before the first `/`) and version (between `/` and the
//! revision `#`). Deduped by name@version.

use std::collections::HashSet;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct ConanLock;

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    build_requires: Vec<String>,
    #[serde(default)]
    python_requires: Vec<String>,
}

/// Split a Conan reference `name/version#rrev%ts` into (name, version).
/// Returns `None` when there's no `name/version` shape.
fn split_ref(r: &str) -> Option<(&str, &str)> {
    let (name, rest) = r.split_once('/')?;
    if name.is_empty() {
        return None;
    }
    // version ends at the recipe-revision `#` (if any).
    let version = rest.split('#').next().unwrap_or(rest);
    if version.is_empty() {
        return None;
    }
    Some((name, version))
}

impl LockfileParser for ConanLock {
    fn filename(&self) -> &'static str {
        "conan.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Conan
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc =
            serde_json::from_slice(raw).map_err(|e| ParseError(format!("conan.lock: {e}")))?;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for r in doc
            .requires
            .iter()
            .chain(&doc.build_requires)
            .chain(&doc.python_requires)
        {
            let Some((name, version)) = split_ref(r) else {
                continue;
            };
            let key = format!("{name}@{version}");
            if !seen.insert(key) {
                continue;
            }
            out.push(Dependency {
                ecosystem: Ecosystem::Conan,
                name: name.to_string(),
                version: version.to_string(),
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
    fn parses_requires_and_build_requires() {
        let raw = br#"{
            "version": "0.5",
            "requires": [
                "zlib/1.2.13#87a7211557b6690ef5bf7fc599dd8349%1692672717.708",
                "openssl/3.1.0"
            ],
            "build_requires": [
                "cmake/3.27.0#abc123"
            ]
        }"#;
        let deps = ConanLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].ecosystem, Ecosystem::Conan);
        assert_eq!(deps[0].name, "zlib");
        assert_eq!(deps[0].version, "1.2.13");
        let cmake = deps.iter().find(|d| d.name == "cmake").unwrap();
        assert_eq!(cmake.version, "3.27.0");
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let deps = ConanLock.parse(b"{}", &DirectMap::new()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn corrupt_input_errors() {
        assert!(ConanLock.parse(b"not json", &DirectMap::new()).is_err());
    }
}
