//! npm `package-lock.json` parser (v1 / v2 / v3). Port of
//! `lockfile_npm.go`.

use std::collections::{HashMap, HashSet};

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct PackageLockJson;

impl LockfileParser for PackageLockJson {
    fn filename(&self) -> &'static str {
        "package-lock.json"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
    fn parse(&self, raw: &[u8], direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        parse_npm_lock(raw, direct)
    }
}

#[derive(Deserialize, Default)]
struct V2Pkg {
    #[serde(default)]
    version: String,
    #[serde(default)]
    integrity: String,
    #[serde(default)]
    dependencies: HashMap<String, String>,
}

#[derive(Deserialize, Default)]
struct V1Dep {
    #[serde(default)]
    version: String,
    #[serde(default)]
    integrity: String,
    #[serde(default)]
    dependencies: HashMap<String, V1Dep>,
}

#[derive(Deserialize, Default)]
struct Lockfile {
    #[serde(default)]
    packages: HashMap<String, V2Pkg>,
    #[serde(default)]
    dependencies: HashMap<String, V1Dep>,
}

/// Parse package-lock.json. Understands the v2/v3 flat `packages` map
/// and falls back to the v1 recursive `dependencies` tree.
pub fn parse_npm_lock(raw: &[u8], direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
    let lf: Lockfile = serde_json::from_slice(raw)
        .map_err(|e| ParseError(format!("decode package-lock.json: {e}")))?;

    let mut deps = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    if !lf.packages.is_empty() {
        // First pass: name → shallowest resolved version, for depends_on.
        let mut name_to_version: HashMap<String, (usize, String)> = HashMap::new();
        for (path, p) in &lf.packages {
            if path.is_empty() || p.version.is_empty() {
                continue;
            }
            let name = name_from_npm_path(path);
            if name.is_empty() {
                continue;
            }
            let depth = path.len();
            match name_to_version.get(name) {
                Some((prev_depth, _)) if *prev_depth <= depth => {}
                _ => {
                    name_to_version.insert(name.to_string(), (depth, p.version.clone()));
                }
            }
        }

        for (path, p) in &lf.packages {
            if path.is_empty() || p.version.is_empty() {
                continue;
            }
            let name = name_from_npm_path(path);
            if name.is_empty() {
                continue;
            }
            let key = format!("{name}@{}", p.version);
            if !seen.insert(key) {
                continue;
            }
            let mut depends_on: Vec<String> = Vec::new();
            for dep_name in p.dependencies.keys() {
                if let Some((_, ver)) = name_to_version.get(dep_name) {
                    depends_on.push(format!("{}/{dep_name}@{ver}", Ecosystem::Npm.as_str()));
                }
            }
            deps.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: p.version.clone(),
                integrity: p.integrity.clone(),
                direct: direct.get(name).copied().unwrap_or(false),
                depends_on,
                ..Default::default()
            });
        }
        return Ok(deps);
    }

    // v1 fallback: recursive dependencies tree.
    walk_v1(&lf.dependencies, direct, &mut seen, &mut deps);
    Ok(deps)
}

fn walk_v1(
    node: &HashMap<String, V1Dep>,
    direct: &DirectMap,
    seen: &mut HashSet<String>,
    out: &mut Vec<Dependency>,
) {
    for (name, d) in node {
        if !d.version.is_empty() {
            let key = format!("{name}@{}", d.version);
            if seen.insert(key) {
                out.push(Dependency {
                    ecosystem: Ecosystem::Npm,
                    name: name.clone(),
                    version: d.version.clone(),
                    integrity: d.integrity.clone(),
                    direct: direct.get(name).copied().unwrap_or(false),
                    ..Default::default()
                });
            }
        }
        if !d.dependencies.is_empty() {
            walk_v1(&d.dependencies, direct, seen, out);
        }
    }
}

/// Package name = everything after the LAST "node_modules/" segment.
/// Scoped names survive (one slash after the @scope). Mirrors
/// `nameFromNpmPath`.
fn name_from_npm_path(p: &str) -> &str {
    const MARKER: &str = "node_modules/";
    match p.rfind(MARKER) {
        Some(idx) => &p[idx + MARKER.len()..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v3_packages_map_with_graph() {
        let raw = br#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root" },
                "node_modules/lodash": { "version": "4.17.21", "integrity": "sha512-x" },
                "node_modules/express": {
                    "version": "4.18.2",
                    "dependencies": { "lodash": "^4" }
                }
            }
        }"#;
        let direct: DirectMap = [("express".to_string(), true)].into_iter().collect();
        let mut deps = parse_npm_lock(raw, &direct).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(deps.len(), 2);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert!(express.direct);
        assert_eq!(express.depends_on, vec!["npm/lodash@4.17.21"]);

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert!(!lodash.direct);
        assert_eq!(lodash.integrity, "sha512-x");
    }

    #[test]
    fn parses_v1_nested_tree_deduped() {
        let raw = br#"{
            "lockfileVersion": 1,
            "dependencies": {
                "a": {
                    "version": "1.0.0",
                    "dependencies": { "b": { "version": "2.0.0" } }
                },
                "b": { "version": "2.0.0" }
            }
        }"#;
        let deps = parse_npm_lock(raw, &DirectMap::new()).unwrap();
        // b appears twice but dedupes on name@version.
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let deps = parse_npm_lock(b"{}", &DirectMap::new()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn scoped_name_survives() {
        assert_eq!(name_from_npm_path("node_modules/@scope/pkg"), "@scope/pkg");
        assert_eq!(
            name_from_npm_path("node_modules/foo/node_modules/bar"),
            "bar"
        );
        assert_eq!(name_from_npm_path("no-marker"), "");
    }
}
