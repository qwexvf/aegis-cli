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
                in_block = true;
                continue;
            }
            if !in_block {
                continue;
            }
            let l = line.trim();
            if let Some(after) = l.strip_prefix("version ") {
                let ver = after.trim_matches(|c| c == ' ' || c == '"');
                if cur_name.is_empty() || ver.is_empty() {
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
    fn header_name_extraction() {
        assert_eq!(first_yarn_header_name("\"lodash@^4.17.0\""), "lodash");
        assert_eq!(
            first_yarn_header_name("@types/lodash@npm:^4.14.0"),
            "@types/lodash"
        );
        assert_eq!(first_yarn_header_name("foo@workspace:packages/foo"), "foo");
    }
}
