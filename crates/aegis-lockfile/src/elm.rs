//! Elm `elm.json` parser (application projects).
//!
//! An `application` elm.json pins EXACT versions for both direct and indirect
//! dependencies (Elm resolves the whole graph at add time), so it doubles as a
//! lockfile. Names are `author/project` (e.g. `elm/core`), versions are exact
//! `major.minor.patch`. `package`-type elm.json instead lists version *ranges*
//! and is not a lockfile — those are skipped (`type != "application"`).
//!
//! Deps under `dependencies.direct` / `test-dependencies.direct` are marked
//! direct; the `indirect` buckets are transitive.

use std::collections::BTreeMap;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct ElmJson;

#[derive(Deserialize, Default)]
struct Buckets {
    #[serde(default)]
    direct: BTreeMap<String, String>,
    #[serde(default)]
    indirect: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    dependencies: Buckets,
    #[serde(rename = "test-dependencies", default)]
    test_dependencies: Buckets,
}

impl LockfileParser for ElmJson {
    fn filename(&self) -> &'static str {
        "elm.json"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Elm
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc =
            serde_json::from_slice(raw).map_err(|e| ParseError(format!("elm.json: {e}")))?;
        // Only application elm.json pins exact versions; package-type lists
        // ranges and is not a lockfile.
        if doc.kind != "application" {
            return Ok(Vec::new());
        }
        let mut out: Vec<Dependency> = Vec::new();
        let mut push = |m: &BTreeMap<String, String>, direct: bool| {
            for (name, version) in m {
                if version.is_empty() {
                    continue;
                }
                out.push(Dependency {
                    ecosystem: Ecosystem::Elm,
                    name: name.clone(),
                    version: version.clone(),
                    direct,
                    ..Default::default()
                });
            }
        };
        push(&doc.dependencies.direct, true);
        push(&doc.dependencies.indirect, false);
        push(&doc.test_dependencies.direct, true);
        push(&doc.test_dependencies.indirect, false);
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        out.dedup_by(|a, b| a.name == b.name && a.version == b.version);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_application_direct_and_indirect() {
        let raw = br#"{
            "type": "application",
            "source-directories": ["src"],
            "elm-version": "0.19.1",
            "dependencies": {
                "direct": { "elm/core": "1.0.5", "elm/html": "1.0.0" },
                "indirect": { "elm/virtual-dom": "1.0.3" }
            },
            "test-dependencies": {
                "direct": { "elm-explorations/test": "2.1.1" },
                "indirect": {}
            }
        }"#;
        let deps = ElmJson.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 4);
        let core = deps.iter().find(|d| d.name == "elm/core").unwrap();
        assert_eq!(core.version, "1.0.5");
        assert_eq!(core.ecosystem, Ecosystem::Elm);
        assert!(core.direct);
        assert!(
            !deps
                .iter()
                .find(|d| d.name == "elm/virtual-dom")
                .unwrap()
                .direct
        );
        assert!(
            deps.iter()
                .find(|d| d.name == "elm-explorations/test")
                .unwrap()
                .direct
        );
    }

    #[test]
    fn package_type_is_not_a_lockfile() {
        // ranges, not exact pins → skipped.
        let raw = br#"{
            "type": "package",
            "dependencies": { "elm/core": "1.0.0 <= v < 2.0.0" }
        }"#;
        assert!(ElmJson.parse(raw, &DirectMap::new()).unwrap().is_empty());
    }

    #[test]
    fn corrupt_json_errors() {
        assert!(ElmJson.parse(b"nope", &DirectMap::new()).is_err());
    }
}
