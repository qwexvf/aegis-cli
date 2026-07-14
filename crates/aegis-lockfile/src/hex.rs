//! Hex parsers. Port of `lockfile_gleam.go` + `lockfile_mix.go`. Both
//! resolve to the `hex` ecosystem. Gleam's `manifest.toml` is an array
//! of inline tables; Elixir's `mix.lock` is an Elixir term map.

use aegis_domain::{Dependency, Ecosystem};
use regex::Regex;
use std::sync::OnceLock;

use crate::{DirectMap, LockfileParser, ParseError};

// --- Gleam manifest.toml ---------------------------------------------

pub struct GleamManifest;

impl LockfileParser for GleamManifest {
    fn filename(&self) -> &'static str {
        "manifest.toml"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Hex
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        let mut in_packages = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !in_packages {
                if line.starts_with("packages") && line.contains('=') {
                    in_packages = true;
                }
                continue;
            }
            if line == "]" {
                break;
            }
            if !line.starts_with('{') {
                continue;
            }
            let (Some(name), Some(version)) = (
                inline_table_field(line, "name"),
                inline_table_field(line, "version"),
            ) else {
                continue;
            };
            out.push(Dependency {
                ecosystem: Ecosystem::Hex,
                name,
                version,
                ..Default::default()
            });
        }
        Ok(out)
    }
}

/// Extract the quoted value for `key` from an inline TOML table string,
/// e.g. `{ name = "foo", version = "1.0" }`. Mirrors `inlineTableField`.
fn inline_table_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = \"");
    let idx = line.find(&needle)?;
    let start = idx + needle.len();
    let end = line[start..].find('"')?;
    Some(line[start..start + end].to_string())
}

// --- Elixir mix.lock -------------------------------------------------

pub struct MixLock;

fn mix_hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\s*"([^"]+)":\s*\{:hex,\s*:\w+,\s*"([^"]+)""#).unwrap())
}
fn mix_git_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\s*"([^"]+)":\s*\{:git,\s*"([^"]+)""#).unwrap())
}

impl LockfileParser for MixLock {
    fn filename(&self) -> &'static str {
        "mix.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Hex
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        for line in text.lines() {
            if let Some(m) = mix_hex_re().captures(line) {
                out.push(Dependency {
                    ecosystem: Ecosystem::Hex,
                    name: m[1].to_string(),
                    version: m[2].to_string(),
                    ..Default::default()
                });
                continue;
            }
            if let Some(m) = mix_git_re().captures(line) {
                // git dep: empty version → OSV lookup skipped.
                out.push(Dependency {
                    ecosystem: Ecosystem::Hex,
                    name: m[1].to_string(),
                    version: String::new(),
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
    fn gleam_inline_tables() {
        let raw = b"packages = [\n\
                    \x20\x20{ name = \"gleam_stdlib\", version = \"0.34.0\", build_tools = [\"gleam\"] },\n\
                    \x20\x20{ name = \"gleeunit\", version = \"1.0.2\" },\n\
                    ]\n";
        let deps = GleamManifest.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "gleam_stdlib");
        assert_eq!(deps[0].version, "0.34.0");
        assert_eq!(deps[0].ecosystem, Ecosystem::Hex);
    }

    #[test]
    fn mix_hex_and_git() {
        let raw = b"%{\n\
                    \x20\x20\"cowboy\": {:hex, :cowboy, \"2.10.0\", \"hash\", [:rebar3], []},\n\
                    \x20\x20\"phoenix\": {:git, \"https://github.com/x/phoenix\", \"sha\", []},\n\
                    }\n";
        let deps = MixLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "cowboy");
        assert_eq!(deps[0].version, "2.10.0");
        assert_eq!(deps[1].name, "phoenix");
        assert_eq!(deps[1].version, ""); // git dep
    }
}
