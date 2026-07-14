//! Perl `cpanfile.snapshot` (Carton) parser. Port of `lockfile_cpan.go`.
//! OSV "CPAN" keys on the distribution name (hyphenated), extracted from
//! the tarball filename in each `pathname:` line.

use std::collections::HashSet;
use std::sync::OnceLock;

use aegis_domain::{Dependency, Ecosystem};
use regex::Regex;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct CpanfileSnapshot;

fn pathname_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"pathname:\s+(?:[^/]+/)*([A-Za-z][A-Za-z0-9._-]*)-(\d[^/]*?)\.tar\.gz\s*$")
            .unwrap()
    })
}

impl LockfileParser for CpanfileSnapshot {
    fn filename(&self) -> &'static str {
        "cpanfile.snapshot"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cpan
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for line in text.lines() {
            if !line.contains("pathname:") {
                continue;
            }
            let Some(m) = pathname_re().captures(line) else {
                continue;
            };
            let name = m[1].to_string();
            let ver = m[2].to_string();
            let key = format!("{name}@{ver}");
            if !seen.insert(key) {
                continue;
            }
            out.push(Dependency {
                ecosystem: Ecosystem::Cpan,
                name,
                version: ver,
                ..Default::default()
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_name_version_from_pathname() {
        let raw = b"DISTRIBUTIONS\n\
                    \x20\x20Module-CPANfile-1.1004\n\
                    \x20\x20\x20\x20pathname: M/MI/MIYAGAWA/Module-CPANfile-1.1004.tar.gz\n\
                    \x20\x20\x20\x20provides:\n";
        let deps = CpanfileSnapshot.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Module-CPANfile");
        assert_eq!(deps[0].version, "1.1004");
        assert_eq!(deps[0].ecosystem, Ecosystem::Cpan);
    }
}
