//! `yarn.lock` parser (classic v1 + berry v2/3/4). Port of
//! `lockfile_yarn.go`. npm ecosystem.
//!
//! Blocks of `"name@range", "name@range":` header lines followed by an
//! indented `version "X.Y.Z"`. One entry per (name, version).

use std::collections::HashSet;

use aegis_domain::{Dependency, Ecosystem};

use crate::{DirectMap, LockfileParser, ParseError};

pub struct YarnLock;

impl LockfileParser for YarnLock {
    fn filename(&self) -> &'static str {
        "yarn.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
    fn parse(&self, raw: &[u8], direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut deps = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut cur_name = String::new();
        let mut in_block = false;
        // berry marks the root project and each workspace with a
        // `resolution: "name@workspace:path"`. Those are local directories,
        // not registry packages: looked up they 404, which under a fail-closed
        // gate blocks the install, and `sbom` emitted them as components with
        // a bogus `0.0.0-use.local` version.
        let mut cur_is_workspace = false;

        for line in text.lines() {
            if line.trim().is_empty() {
                in_block = false;
                cur_name.clear();
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            // Block header: column 0, ends with ":".
            if !line.starts_with(' ') && line.ends_with(':') {
                let header = &line[..line.len() - 1];
                cur_name = first_yarn_header_name(header);
                // berry's `__metadata:` block carries a `version:` (the lockfile
                // cache version), not a package — don't emit it as a dep.
                if cur_name == "__metadata" {
                    cur_name.clear();
                }
                // The header carries the protocol in both dialects, and it is
                // the only place that works for classic v1, where `version`
                // precedes `resolved` inside the block.
                cur_is_workspace = ["@workspace:", "@file:", "@link:", "@portal:"]
                    .iter()
                    .any(|p| header.contains(p));
                in_block = true;
                continue;
            }
            if !in_block {
                continue;
            }
            let l = line.trim();
            // ...and so does the `resolution:` line, for classic-style headers.
            if let Some(r) = l.strip_prefix("resolution:") {
                if r.contains("@workspace:") {
                    cur_is_workspace = true;
                }
            }
            // Classic v1 has no `@workspace:` protocol; it points a local
            // package at a directory with `resolved "file:packages/x"`. Those
            // carry an ordinary version (1.0.0), so the berry check above does
            // not see them, and they were emitted as registry packages.
            if let Some(r) = l.strip_prefix("resolved ") {
                let r = r.trim().trim_matches('"');
                if r.starts_with("file:") || r.starts_with("link:") || r.starts_with("portal:") {
                    cur_is_workspace = true;
                }
            }
            // classic v1 writes `version "X"` (space + quotes); berry v2/3/4
            // writes `version: X` / `version: "X"` (colon, quotes optional).
            let after = l
                .strip_prefix("version ")
                .or_else(|| l.strip_prefix("version:"));
            if let Some(after) = after {
                let ver = after.trim_matches(|c| c == ' ' || c == '"' || c == ':');
                if cur_name.is_empty() || ver.is_empty() || cur_is_workspace {
                    continue;
                }
                let key = format!("{cur_name}@{ver}");
                if !seen.insert(key) {
                    continue;
                }
                deps.push(Dependency {
                    ecosystem: Ecosystem::Npm,
                    name: cur_name.clone(),
                    version: ver.to_string(),
                    direct: direct.get(&cur_name).copied().unwrap_or(false),
                    ..Default::default()
                });
            }
        }
        Ok(deps)
    }
}

/// Package name from the first constraint in a yarn header. Handles
/// scoped names (the first `@` is the scope marker). Mirrors
/// `firstYarnHeaderName`.
fn first_yarn_header_name(header: &str) -> String {
    let first = header
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"');
    if let Some(rest) = first.strip_prefix('@') {
        // scoped: look for the SECOND '@'.
        match rest.split_once('@') {
            Some((before, _)) => format!("@{before}"),
            None => first.to_string(),
        }
    } else if let Some(idx) = first.find('@') {
        if idx > 0 {
            first[..idx].to_string()
        } else {
            first.to_string()
        }
    } else {
        first.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocks_and_scoped_names() {
        let raw = b"# yarn lockfile v1\n\
                    \n\
                    \"lodash@^4.17.0\", \"lodash@^4.17.21\":\n\
                    \x20\x20version \"4.17.21\"\n\
                    \n\
                    \"@types/node@^20.0.0\":\n\
                    \x20\x20version \"20.11.5\"\n";
        let deps = YarnLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "lodash");
        assert_eq!(deps[0].version, "4.17.21");
        assert_eq!(deps[1].name, "@types/node");
    }

    #[test]
    fn parses_berry_colon_version_form() {
        // yarn berry (v2/3/4): `"name@npm:range":` header + `  version: X`
        // (colon form, quotes optional) — previously dropped silently.
        let raw = b"# This file is generated by running \"yarn install\"\n\
                    __metadata:\n\
                    \x20\x20version: 8\n\
                    \n\
                    \"lodash@npm:^4.17.21\":\n\
                    \x20\x20version: 4.17.21\n\
                    \x20\x20resolution: \"lodash@npm:4.17.21\"\n\
                    \n\
                    \"@types/node@npm:^20.0.0\":\n\
                    \x20\x20version: \"20.11.5\"\n";
        let deps = YarnLock.parse(raw, &DirectMap::new()).unwrap();
        // __metadata's `version: 8` has no cur_name (header ends without a real
        // package) — but its block header `__metadata:` sets cur_name="__metadata";
        // assert the two real packages are present regardless.
        assert!(
            deps.iter()
                .any(|d| d.name == "lodash" && d.version == "4.17.21"),
            "berry unquoted version missed: {deps:?}"
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "@types/node" && d.version == "20.11.5"),
            "berry quoted version missed: {deps:?}"
        );
    }

    #[test]
    fn header_name_extraction() {
        assert_eq!(first_yarn_header_name("\"lodash@^4.17.0\""), "lodash");
        assert_eq!(
            first_yarn_header_name("@types/lodash@npm:^4.14.0"),
            "@types/lodash"
        );
        assert_eq!(first_yarn_header_name("foo@workspace:packages/foo"), "foo");
    }
    #[test]
    fn berry_workspaces_are_not_registry_packages() {
        // The root project and every workspace get a `@workspace:` resolution
        // and a `0.0.0-use.local` version. Emitting them meant a 404 on the
        // registry — a blocked install under a fail-closed gate — and bogus
        // SBOM components.
        let raw = br#"__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  linkType: hard

"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
  linkType: soft

"@acme/pkg@workspace:packages/pkg":
  version: 0.0.0-use.local
  resolution: "@acme/pkg@workspace:packages/pkg"
  linkType: soft
"#;
        let deps = YarnLock.parse(raw, &DirectMap::new()).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["lodash"], "workspaces leaked in: {names:?}");
    }
    #[test]
    fn classic_v1_file_resolutions_are_not_registry_packages() {
        // v1 has no `@workspace:` protocol: a local package is pointed at a
        // directory by `resolved "file:..."` and carries an ordinary version,
        // so the berry check does not see it.
        let raw = br#"# yarn lockfile v1

lodash@4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"

"@acme/local@file:packages/local":
  version "1.0.0"
  resolved "file:packages/local"
"#;
        let deps = YarnLock.parse(raw, &DirectMap::new()).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["lodash"], "local package leaked in: {names:?}");
    }
}
