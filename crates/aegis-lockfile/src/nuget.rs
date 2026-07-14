//! NuGet `packages.lock.json` parser. Port of `lockfile_nuget.go`.
//!
//! Flattens across all target frameworks (a package may appear under
//! multiple TFMs with the same resolved version; deduped by name@version).
//! `type: "Direct"` marks csproj-declared deps.

use std::collections::HashMap;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct PackagesLockJson;

#[derive(Deserialize, Default)]
struct Entry {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    resolved: String,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    dependencies: HashMap<String, HashMap<String, Entry>>,
}

impl LockfileParser for PackagesLockJson {
    fn filename(&self) -> &'static str {
        "packages.lock.json"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc = serde_json::from_slice(raw)
            .map_err(|e| ParseError(format!("packages.lock.json: {e}")))?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for pkgs in doc.dependencies.values() {
            for (name, e) in pkgs {
                if e.resolved.is_empty() {
                    continue;
                }
                let key = format!("{name}@{}", e.resolved);
                if !seen.insert(key) {
                    continue;
                }
                out.push(Dependency {
                    ecosystem: Ecosystem::NuGet,
                    name: name.clone(),
                    version: e.resolved.clone(),
                    direct: e.kind == "Direct",
                    ..Default::default()
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_tfms_and_marks_direct() {
        let raw = br#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" },
                    "System.Buffers": { "type": "Transitive", "resolved": "4.5.1" }
                },
                "net6.0": {
                    "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" }
                }
            }
        }"#;
        let deps = PackagesLockJson.parse(raw, &DirectMap::new()).unwrap();
        // Newtonsoft dedupes across the two TFMs.
        assert_eq!(deps.len(), 2);
        let nj = deps.iter().find(|d| d.name == "Newtonsoft.Json").unwrap();
        assert!(nj.direct);
        assert!(
            !deps
                .iter()
                .find(|d| d.name == "System.Buffers")
                .unwrap()
                .direct
        );
    }
}
