//! Rust `Cargo.lock` parser. Port of `lockfile_cargo.go`.
//!
//! Structurally identical to poetry.lock / uv.lock — a series of
//! `[[package]]` tables — so it reuses the shared TOML reader. Cargo's
//! extra fields (source, dependencies, checksum) are ignored. All
//! entries are treated as transitive; direct-vs-transitive lives in
//! Cargo.toml, which this parser doesn't read.

use aegis_domain::{Dependency, Ecosystem};

use crate::common::parse_toml_packages;
use crate::{DirectMap, LockfileParser, ParseError};

pub struct CargoLock;

impl LockfileParser for CargoLock {
    fn filename(&self) -> &'static str {
        "Cargo.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Crates
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        Ok(parse_toml_packages(raw)
            .into_iter()
            .map(|p| Dependency {
                ecosystem: Ecosystem::Crates,
                name: p.name,
                version: p.version,
                ..Default::default()
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_tables() {
        let raw = br#"
version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "libc"
version = "0.2.153"
"#;
        let deps = CargoLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, Ecosystem::Crates);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.197");
    }
}
