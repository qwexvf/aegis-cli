//! R `renv.lock` parser. Port of `lockfile_renv.go`.
//!
//! JSON with a `Packages` map. CRAN/Bioconductor packages match OSV
//! "CRAN"; git-sourced packages are recorded with their version but
//! won't match OSV (correct — they aren't in the registry). All treated
//! as transitive.

use std::collections::HashMap;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct RenvLock;

#[derive(Deserialize, Default)]
struct Pkg {
    #[serde(rename = "Package", default)]
    package: String,
    #[serde(rename = "Version", default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(rename = "Packages", default)]
    packages: HashMap<String, Pkg>,
}

impl LockfileParser for RenvLock {
    fn filename(&self) -> &'static str {
        "renv.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cran
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc = serde_json::from_slice(raw)
            .map_err(|e| ParseError(format!("renv.lock decode: {e}")))?;
        Ok(doc
            .packages
            .into_values()
            .filter(|p| !p.package.is_empty() && !p.version.is_empty())
            .map(|p| Dependency {
                ecosystem: Ecosystem::Cran,
                name: p.package,
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
    fn parses_packages_map() {
        let raw = br#"{
            "R": { "Version": "4.3.1" },
            "Packages": {
                "ggplot2": { "Package": "ggplot2", "Version": "3.4.4", "Source": "Repository" },
                "myGitPkg": { "Package": "myGitPkg", "Version": "1.0.0", "Source": "GitHub" }
            }
        }"#;
        let mut deps = RenvLock.parse(raw, &DirectMap::new()).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, Ecosystem::Cran);
        assert_eq!(deps[0].name, "ggplot2");
        assert_eq!(deps[0].version, "3.4.4");
    }
}
