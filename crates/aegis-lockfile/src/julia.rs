//! Julia `Manifest.toml` parser.
//!
//! A Julia manifest lists resolved packages as `[[deps.PkgName]]` array-of-
//! tables, each with an optional `version = "..."` (stdlib entries carry a
//! uuid but no version — those are skipped). The package name lives in the
//! table header, not a `name =` key, so this can't reuse the shared
//! `[[package]]` TOML reader; it scans headers and `version` lines directly.

use aegis_domain::{Dependency, Ecosystem};

use crate::{DirectMap, LockfileParser, ParseError};

pub struct JuliaManifest;

/// Pull the package name from a `[[deps.NAME]]` header, or `None` for any
/// other line.
fn deps_header_name(line: &str) -> Option<&str> {
    let inner = line.strip_prefix("[[deps.")?.strip_suffix("]]")?;
    if inner.is_empty() {
        None
    } else {
        Some(inner)
    }
}

impl LockfileParser for JuliaManifest {
    fn filename(&self) -> &'static str {
        "Manifest.toml"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Julia
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| ParseError(format!("Manifest.toml: invalid utf-8: {e}")))?;

        let mut out = Vec::new();
        let mut cur_name: Option<String> = None;
        let mut cur_version: Option<String> = None;

        // Emit the in-progress package if it has both a name and a version.
        fn flush(
            name: &mut Option<String>,
            version: &mut Option<String>,
            out: &mut Vec<Dependency>,
        ) {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                out.push(Dependency {
                    ecosystem: Ecosystem::Julia,
                    name: n,
                    version: v,
                    ..Default::default()
                });
            }
            // drop a name with no version (stdlib entry).
            *name = None;
            *version = None;
        }

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = deps_header_name(line) {
                flush(&mut cur_name, &mut cur_version, &mut out);
                cur_name = Some(name.to_string());
                continue;
            }
            // Any other table header ends the current package block.
            if line.starts_with('[') {
                flush(&mut cur_name, &mut cur_version, &mut out);
                continue;
            }
            if cur_name.is_some() && line.starts_with("version") {
                if let Some(v) = crate::common::toml_string(line) {
                    cur_version = Some(v);
                }
            }
        }
        flush(&mut cur_name, &mut cur_version, &mut out);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_deps_tables_with_versions() {
        let raw = br#"
julia_version = "1.9.0"
manifest_format = "2.0"

[[deps.ArgTools]]
uuid = "0dad84c5-d112-42e6-8d28-ef12dabb789f"
version = "1.1.1"

[[deps.JSON]]
deps = ["Dates", "Mmap", "Parsers"]
git-tree-sha1 = "31e996f0a15c7b280ba9f76636b3ff9e2ae58c9a"
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
"#;
        let deps = JuliaManifest.parse(raw, &DirectMap::new()).unwrap();
        // Dates has no version → skipped.
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, Ecosystem::Julia);
        assert_eq!(deps[0].name, "ArgTools");
        assert_eq!(deps[0].version, "1.1.1");
        assert_eq!(deps[1].name, "JSON");
        assert_eq!(deps[1].version, "0.21.4");
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let deps = JuliaManifest.parse(b"", &DirectMap::new()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn invalid_utf8_errors() {
        assert!(JuliaManifest.parse(&[0xff, 0xfe], &DirectMap::new()).is_err());
    }
}
