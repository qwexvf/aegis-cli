//! PHP `composer.lock` parser. Port of `lockfile_composer.go`.
//!
//! JSON with a `packages` array (runtime deps); `packages-dev` is
//! skipped — dev-only deps don't ship on Packagist install. Names are
//! canonical "vendor/package". All treated as transitive.

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct ComposerLock;

#[derive(Deserialize)]
struct Pkg {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    packages: Vec<Pkg>,
}

impl LockfileParser for ComposerLock {
    fn filename(&self) -> &'static str {
        "composer.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc =
            serde_json::from_slice(raw).map_err(|e| ParseError(format!("composer.lock: {e}")))?;
        Ok(doc
            .packages
            .into_iter()
            .filter(|p| !p.name.is_empty() && !p.version.is_empty())
            .map(|p| Dependency {
                ecosystem: Ecosystem::Packagist,
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
    fn parses_packages_skips_dev() {
        let raw = br#"{
            "packages": [
                { "name": "monolog/monolog", "version": "3.5.0" },
                { "name": "guzzlehttp/guzzle", "version": "7.8.1" }
            ],
            "packages-dev": [ { "name": "phpunit/phpunit", "version": "10.5.0" } ]
        }"#;
        let deps = ComposerLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, Ecosystem::Packagist);
        assert_eq!(deps[0].name, "monolog/monolog");
    }
}
