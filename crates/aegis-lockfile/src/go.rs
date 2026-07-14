//! Go `go.sum` parser. Port of `lockfile_go.go`.
//!
//! Each module has two lines (`… vX` and `… vX/go.mod`); we dedupe per
//! (module, version). Pseudo-versions (`v0.0.0-…`) are kept verbatim —
//! OSV.dev's Go ecosystem matches the same string. Everything is
//! transitive; go.sum lists the whole module graph.

use std::collections::HashSet;

use aegis_domain::{Dependency, Ecosystem};

use crate::{DirectMap, LockfileParser, ParseError};

pub struct GoSum;

impl LockfileParser for GoSum {
    fn filename(&self) -> &'static str {
        "go.sum"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        parse_go_sum(raw)
    }
}

/// Valid go.sum module-path charset. Go escapes uppercase as "!x", so
/// paths are lowercase + digits + a few separators. Rejects control
/// chars/spaces. Mirrors `goModulePathPattern` + `isValidGoModulePath`.
fn is_valid_go_module_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'!' | b'+' | b'-')
        })
}

fn parse_go_sum(raw: &[u8]) -> Result<Vec<Dependency>, ParseError> {
    let text = String::from_utf8_lossy(raw);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A go.sum line is exactly "<module> <version> <h1:hash>".
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 {
            continue;
        }
        let module = fields[0];
        let version = fields[1].strip_suffix("/go.mod").unwrap_or(fields[1]);
        if !version.starts_with('v') || !fields[2].starts_with("h1:") {
            continue;
        }
        if !is_valid_go_module_path(module) {
            continue;
        }
        let key = format!("{module}@{version}");
        if !seen.insert(key) {
            continue;
        }
        out.push(Dependency {
            ecosystem: Ecosystem::Go,
            name: module.to_string(),
            version: version.to_string(),
            ..Default::default()
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_module_and_gomod_lines() {
        let raw = b"github.com/foo/bar v1.2.3 h1:abc=\n\
                    github.com/foo/bar v1.2.3/go.mod h1:def=\n\
                    github.com/baz/qux v0.0.0-20200101000000-abcdef123456 h1:ghi=\n";
        let deps = parse_go_sum(raw).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/foo/bar");
        assert_eq!(deps[0].version, "v1.2.3");
        // pseudo-version kept verbatim.
        assert_eq!(deps[1].version, "v0.0.0-20200101000000-abcdef123456");
    }

    #[test]
    fn rejects_junk_and_unpinned() {
        let raw = b"not a real line\n\
                    github.com/x/y notaversion h1:abc=\n\
                    github.com/x/y v1.0.0 notahash\n";
        assert!(parse_go_sum(raw).unwrap().is_empty());
    }
}
