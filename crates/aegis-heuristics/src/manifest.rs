//! Manifest parsers that build a [`NormalizedPackage`] from a raw package
//! manifest. Port of the `*Parser.Parse` methods in `heuristics` (currently
//! npm; other ecosystems follow the same shape).
//!
//! The parser's job is to classify each dependency's [`DepSource`] and pull
//! install-time lifecycle hooks out of the manifest, so the metadata-based
//! detectors ([`crate::deps`], install-hook) have structured input.

use std::collections::HashMap;

use aegis_domain::Ecosystem;
use serde_json::Value;

use crate::{Dep, DepSource, Hook, NormalizedPackage};

/// npm install-time lifecycle phases. The other scripts (test/start/build/…)
/// don't run at `npm install` time and aren't supply-chain vectors.
const NPM_INSTALL_PHASES: [&str; 4] = ["preinstall", "install", "postinstall", "prepare"];

/// Build a [`NormalizedPackage`] from an npm `package.json`. Unparseable
/// manifests degrade gracefully to identity + files only (matches the Go
/// parser: "no deps" is treated the same as "couldn't read").
pub fn parse_npm_manifest(
    name: &str,
    manifest_raw: &[u8],
    files: HashMap<String, Vec<u8>>,
) -> NormalizedPackage {
    let mut pkg = NormalizedPackage {
        name: name.to_string(),
        ecosystem_name: Some(Ecosystem::Npm),
        files,
        manifest_raw: manifest_raw.to_vec(),
        ..Default::default()
    };
    if manifest_raw.is_empty() {
        return pkg;
    }
    let root: Value = match serde_json::from_slice(manifest_raw) {
        Ok(v) => v,
        Err(_) => return pkg,
    };

    if let Some(n) = root.get("name").and_then(Value::as_str) {
        if !n.is_empty() {
            pkg.name = n.to_string();
        }
    }

    for (field, group) in [
        ("dependencies", "direct"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ] {
        if let Some(obj) = root.get(field).and_then(Value::as_object) {
            for (dep_name, spec_val) in obj {
                let spec = spec_val.as_str().unwrap_or("").to_string();
                pkg.deps.push(Dep {
                    name: dep_name.clone(),
                    source: classify_npm_dep_source(&spec),
                    spec,
                    groups: vec![group.to_string()],
                });
            }
        }
    }

    if let Some(scripts) = root.get("scripts").and_then(Value::as_object) {
        for phase in NPM_INSTALL_PHASES {
            if let Some(body) = scripts.get(phase).and_then(Value::as_str) {
                if !body.is_empty() {
                    pkg.hooks.push(Hook {
                        phase: phase.to_string(),
                        body: body.to_string(),
                    });
                }
            }
        }
    }

    pkg
}

/// Pull the npm `files` allowlist field out of a raw package.json. Empty
/// on unparseable input or a missing field.
pub fn extract_package_files_field(manifest_raw: &[u8]) -> Vec<String> {
    if manifest_raw.is_empty() {
        return Vec::new();
    }
    let root: Value = match serde_json::from_slice(manifest_raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    root.get("files")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Classify an npm version spec into a [`DepSource`].
pub fn classify_npm_dep_source(spec: &str) -> DepSource {
    let spec = spec.trim();
    if is_git_dep_spec(spec) {
        return DepSource::Vcs;
    }
    if spec.starts_with("file:") || spec.starts_with("./") || spec.starts_with("../") {
        return DepSource::Local;
    }
    DepSource::Registry
}

/// True when a dependency version spec resolves to a git source rather than a
/// semver range. Covers every form npm accepts: `github:`/`gitlab:`/`bitbucket:`/
/// `sourcehut:` shorthand, `git+https://`/`git+ssh://`/`git://` URLs, and bare
/// `org/repo#<40-hex commit SHA>` (npm resolves this as GitHub). Semver ranges
/// (`^`, `~`, `*`, `x.y.z`, `workspace:`) are excluded.
pub fn is_git_dep_spec(spec: &str) -> bool {
    let spec = spec.trim();
    if spec.is_empty() {
        return false;
    }
    const GIT_PREFIXES: [&str; 8] = [
        "github:",
        "gitlab:",
        "bitbucket:",
        "sourcehut:",
        "git+https://",
        "git+ssh://",
        "git+http://",
        "git://",
    ];
    if GIT_PREFIXES.iter().any(|p| spec.starts_with(p)) {
        return true;
    }
    // Bare "user/repo#<ref>": only flag a 40-hex commit SHA pin — the
    // attack-specific shape — to avoid false positives on tag pins.
    if let Some((_, reference)) = spec.split_once('#') {
        if is_commit_sha(reference) {
            return true;
        }
    }
    false
}

/// True when `s` looks like a full 40-character hex SHA1.
fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{check_optional_git_dep, check_vcs_deps};
    use aegis_domain::Capability;

    fn parse(manifest: &str) -> NormalizedPackage {
        parse_npm_manifest("", manifest.as_bytes(), HashMap::new())
    }

    #[test]
    fn github_shorthand_with_sha_is_vcs() {
        assert!(is_git_dep_spec(
            "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
        ));
    }

    #[test]
    fn git_url_forms_are_vcs() {
        for s in [
            "git+https://github.com/attacker/evil.git#aabbcc1122334455667788990011223344556677",
            "git+ssh://git@github.com/org/repo.git#aabbcc1122334455667788990011223344556677",
            "gitlab:org/repo#aabbcc1122334455667788990011223344556677",
            "bitbucket:org/repo#aabbcc1122334455667788990011223344556677",
            "git://example.com/x.git",
        ] {
            assert!(is_git_dep_spec(s), "{s}");
        }
    }

    #[test]
    fn bare_shorthand_sha_is_vcs_but_tag_is_not() {
        assert!(is_git_dep_spec(
            "user/repo#aabbcc1122334455667788990011223344556677"
        ));
        // legitimate tag pin — not a 40-hex SHA
        assert!(!is_git_dep_spec("user/repo#v1.2.3"));
    }

    #[test]
    fn semver_ranges_are_registry() {
        for s in ["^1.2.3", "~1.0.0", "1.2.3", "*", "workspace:*", ">=2.0.0"] {
            assert_eq!(classify_npm_dep_source(s), DepSource::Registry, "{s}");
        }
    }

    #[test]
    fn file_paths_are_local() {
        for s in ["file:../pkg", "./local", "../sibling"] {
            assert_eq!(classify_npm_dep_source(s), DepSource::Local, "{s}");
        }
    }

    #[test]
    fn tanstack_optional_git_dep_incident() {
        // @tanstack/react-router 1.169.5 — github: shorthand + commit SHA in optionalDependencies
        let pkg = parse(
            r#"{
                "name": "@tanstack/react-router",
                "version": "1.169.5",
                "optionalDependencies": {
                    "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
                }
            }"#,
        );
        assert_eq!(pkg.name, "@tanstack/react-router");
        assert_eq!(
            check_optional_git_dep(&pkg),
            vec![Capability::GitDepInOptionalDep]
        );
        assert_eq!(check_vcs_deps(&pkg), vec![Capability::VcsDependency]);
    }

    #[test]
    fn parses_groups_and_hooks() {
        let pkg = parse(
            r#"{
                "dependencies": {"a": "^1.0.0"},
                "devDependencies": {"b": "^2.0.0"},
                "scripts": {
                    "postinstall": "node setup.js",
                    "test": "jest"
                }
            }"#,
        );
        assert_eq!(pkg.deps.len(), 2);
        let a = pkg.deps.iter().find(|d| d.name == "a").unwrap();
        assert_eq!(a.groups, vec!["direct"]);
        let b = pkg.deps.iter().find(|d| d.name == "b").unwrap();
        assert_eq!(b.groups, vec!["dev"]);
        // only install-time hooks captured; "test" dropped
        assert_eq!(pkg.hooks.len(), 1);
        assert_eq!(pkg.hooks[0].phase, "postinstall");
        assert_eq!(pkg.hooks[0].body, "node setup.js");
    }

    #[test]
    fn unparseable_manifest_degrades_to_identity() {
        let pkg = parse_npm_manifest("fallback", b"{ not json", HashMap::new());
        assert_eq!(pkg.name, "fallback");
        assert!(pkg.deps.is_empty());
        assert!(pkg.hooks.is_empty());
    }

    #[test]
    fn empty_manifest_no_deps() {
        let pkg = parse_npm_manifest("x", b"", HashMap::new());
        assert!(pkg.deps.is_empty());
    }
}
