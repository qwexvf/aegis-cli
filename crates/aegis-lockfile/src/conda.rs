//! Conda `conda-lock.yml` parser.
//!
//! conda-lock emits a YAML document with a top-level `package:` list; each
//! entry carries `name` / `version` (plus manager/platform/url we ignore).
//! The same package is listed once per platform, so entries are deduped by
//! name@version.

use std::collections::HashSet;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct CondaLock;

#[derive(Deserialize, Default)]
struct Pkg {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    /// conda-lock records the installer per entry; `pip`-managed packages come
    /// from PyPI and must key advisory lookups against PyPI, not conda.
    #[serde(default)]
    manager: String,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    package: Vec<Pkg>,
}

impl LockfileParser for CondaLock {
    fn filename(&self) -> &'static str {
        "conda-lock.yml"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Conda
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc = serde_yaml_ng::from_slice(raw)
            .map_err(|e| ParseError(format!("conda-lock.yml: {e}")))?;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for p in doc.package {
            if p.name.is_empty() || p.version.is_empty() {
                continue;
            }
            let eco = if p.manager == "pip" {
                Ecosystem::PyPI
            } else {
                Ecosystem::Conda
            };
            let key = format!("{}/{}@{}", eco.as_str(), p.name, p.version);
            if !seen.insert(key) {
                continue;
            }
            out.push(Dependency {
                ecosystem: eco,
                name: p.name,
                version: p.version,
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
    fn parses_package_list_deduped_across_platforms() {
        let raw = br#"
version: 1
metadata:
  content_hash:
    linux-64: abc
package:
  - name: python
    version: "3.11.5"
    manager: conda
    platform: linux-64
  - name: numpy
    version: "1.26.0"
    manager: conda
    platform: linux-64
  - name: python
    version: "3.11.5"
    manager: conda
    platform: osx-64
"#;
        let deps = CondaLock.parse(raw, &DirectMap::new()).unwrap();
        // python listed on two platforms → deduped.
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, Ecosystem::Conda);
        assert_eq!(deps[0].name, "python");
        assert_eq!(deps[0].version, "3.11.5");
        assert_eq!(deps[1].name, "numpy");
        assert_eq!(deps[1].version, "1.26.0");
    }

    #[test]
    fn pip_managed_entries_map_to_pypi() {
        let raw = br#"
package:
  - name: numpy
    version: "1.26.0"
    manager: conda
  - name: requests
    version: "2.31.0"
    manager: pip
"#;
        let deps = CondaLock.parse(raw, &DirectMap::new()).unwrap();
        let numpy = deps.iter().find(|d| d.name == "numpy").unwrap();
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(numpy.ecosystem, Ecosystem::Conda);
        assert_eq!(
            requests.ecosystem,
            Ecosystem::PyPI,
            "pip-managed entry must map to PyPI for correct advisory lookup"
        );
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let deps = CondaLock.parse(b"version: 1\n", &DirectMap::new()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn corrupt_input_errors() {
        assert!(CondaLock
            .parse(b"\t: : broken\n  - [", &DirectMap::new())
            .is_err());
    }
}
