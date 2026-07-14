//! Dart `pubspec.lock` parser. Port of `lockfile_pubspec.go`. Hand-parsed
//! YAML (no dep). sdk/path packages are skipped (no pub.dev version);
//! git packages keep their resolved ref so the VCS heuristic can flag them.

use aegis_domain::{Dependency, Ecosystem};

use crate::{DirectMap, LockfileParser, ParseError};

pub struct PubspecLock;

#[derive(Default)]
struct PkgState {
    name: String,
    source: String,
    version: String,
    direct: bool,
}

impl LockfileParser for PubspecLock {
    fn filename(&self) -> &'static str {
        "pubspec.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pub
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        let mut cur = PkgState::default();
        let mut in_packages = false;
        let mut in_pkg = false;

        let flush = |cur: &PkgState, out: &mut Vec<Dependency>, in_pkg: bool| {
            if !in_pkg || cur.name.is_empty() || cur.version.is_empty() {
                return;
            }
            if cur.source == "sdk" || cur.source == "path" {
                return;
            }
            out.push(Dependency {
                ecosystem: Ecosystem::Pub,
                name: cur.name.clone(),
                version: cur.version.trim_matches('"').to_string(),
                direct: cur.direct,
                ..Default::default()
            });
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !in_packages {
                if trimmed.trim_end_matches(':') == "packages" {
                    in_packages = true;
                }
                continue;
            }
            // "sdks:" ends the packages block.
            if trimmed.trim_end_matches(':') == "sdks" {
                flush(&cur, &mut out, in_pkg);
                in_pkg = false;
                break;
            }
            let indent = line.len() - line.trim_start_matches(' ').len();

            // 2-space indent = new package name.
            if indent == 2 && trimmed.ends_with(':') {
                flush(&cur, &mut out, in_pkg);
                cur = PkgState {
                    name: trimmed.trim_end_matches(':').to_string(),
                    ..Default::default()
                };
                in_pkg = true;
                continue;
            }
            if !in_pkg {
                continue;
            }
            // 4-space indent = package fields.
            if indent == 4 {
                let Some((key, val)) = trimmed.split_once(": ") else {
                    continue;
                };
                let val = val.trim();
                match key {
                    "dependency" => cur.direct = val.contains("direct"),
                    "source" => cur.source = val.trim_matches('"').to_string(),
                    "version" => cur.version = val.trim_matches('"').to_string(),
                    _ => {}
                }
            }
        }
        flush(&cur, &mut out, in_pkg);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosted_skips_sdk() {
        let raw = b"packages:\n\
                    \x20\x20http:\n\
                    \x20\x20\x20\x20dependency: \"direct main\"\n\
                    \x20\x20\x20\x20source: hosted\n\
                    \x20\x20\x20\x20version: \"1.2.0\"\n\
                    \x20\x20flutter:\n\
                    \x20\x20\x20\x20dependency: \"direct main\"\n\
                    \x20\x20\x20\x20source: sdk\n\
                    \x20\x20\x20\x20version: \"0.0.0\"\n\
                    sdks:\n\
                    \x20\x20dart: \">=3.0.0\"\n";
        let deps = PubspecLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "http");
        assert_eq!(deps[0].version, "1.2.0");
        assert!(deps[0].direct);
    }
}
