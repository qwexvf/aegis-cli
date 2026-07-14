//! `bun.lock` parser. Port of `lockfile_bun.go`. npm ecosystem.
//!
//! Bun's text lockfile is JSONC (JSON + comments + trailing commas). We
//! strip comments/trailing commas, then read the flat `packages` map
//! whose values are positional arrays: `["name@version", "integrity", …]`.

use std::collections::HashSet;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct BunLock;

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    packages: std::collections::HashMap<String, Vec<serde_json::Value>>,
}

impl LockfileParser for BunLock {
    fn filename(&self) -> &'static str {
        "bun.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
    fn parse(&self, raw: &[u8], direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let cleaned = strip_json_comments(raw);
        let doc: Doc =
            serde_json::from_slice(&cleaned).map_err(|e| ParseError(format!("bun.lock: {e}")))?;

        let mut deps = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for value in doc.packages.values() {
            let Some(spec) = value.first().and_then(|v| v.as_str()) else {
                continue;
            };
            let integrity = value
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let Some((name, version)) = split_bun_spec(spec) else {
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
                integrity,
                direct: direct.get(name).copied().unwrap_or(false),
                ..Default::default()
            });
        }
        Ok(deps)
    }
}

/// Split "name@version" / "@scope/name@version" on the LAST '@'.
fn split_bun_spec(spec: &str) -> Option<(&str, &str)> {
    let idx = spec.rfind('@')?;
    if idx == 0 {
        return None;
    }
    Some((&spec[..idx], &spec[idx + 1..]))
}

/// Remove `//` and `/* */` comments and trailing commas before `}`/`]`.
/// Minimal viable JSONC; strings (incl. escapes) are respected. Mirrors
/// `stripJSONComments`.
fn strip_json_comments(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    let mut in_string = false;
    while i < raw.len() {
        let c = raw[i];
        if in_string {
            out.push(c);
            if c == b'\\' && i + 1 < raw.len() {
                out.push(raw[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        // Line comment "//".
        if c == b'/' && i + 1 < raw.len() && raw[i + 1] == b'/' {
            while i < raw.len() && raw[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment "/* ... */".
        if c == b'/' && i + 1 < raw.len() && raw[i + 1] == b'*' {
            i += 2;
            while i + 1 < raw.len() && (raw[i] != b'*' || raw[i + 1] != b'/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        // Trailing comma before } or ].
        if c == b',' {
            let mut j = i + 1;
            while j < raw.len() && matches!(raw[j], b' ' | b'\t' | b'\n' | b'\r') {
                j += 1;
            }
            if j < raw.len() && (raw[j] == b'}' || raw[j] == b']') {
                i = j;
                continue;
            }
        }
        if c == b'"' {
            in_string = true;
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jsonc_with_comments_and_trailing_commas() {
        let raw = br#"{
            // bun lockfile
            "lockfileVersion": 1,
            "packages": {
                "lodash": ["lodash@4.17.21", "sha512-x",],
                "@types/node": ["@types/node@20.11.5", "sha512-y"],
            },
        }"#;
        let deps = BunLock.parse(raw, &DirectMap::new()).unwrap();
        let mut names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["@types/node", "lodash"]);
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
        assert_eq!(lodash.integrity, "sha512-x");
    }
}
