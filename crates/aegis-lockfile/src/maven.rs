//! Maven parsers. Port of `lockfile_maven.go`. Two sources:
//! `pom.xml` (direct deps only, via XML) and `gradle.lockfile` (every
//! resolved coordinate, one per line). Canonical name is
//! "groupId:artifactId".

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

// --- pom.xml ---------------------------------------------------------

pub struct PomXml;

#[derive(Deserialize, Default)]
struct Dep {
    #[serde(rename = "groupId", default)]
    group_id: String,
    #[serde(rename = "artifactId", default)]
    artifact_id: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    scope: String,
}

#[derive(Deserialize, Default)]
struct Deps {
    #[serde(default)]
    dependency: Vec<Dep>,
}

#[derive(Deserialize, Default)]
struct Project {
    #[serde(default)]
    dependencies: Deps,
}

impl LockfileParser for PomXml {
    fn filename(&self) -> &'static str {
        "pom.xml"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let project: Project =
            quick_xml::de::from_str(&text).map_err(|e| ParseError(format!("pom.xml: {e}")))?;
        Ok(project
            .dependencies
            .dependency
            .into_iter()
            // test-scope deps don't ship in the published artifact;
            // incomplete entries come from <dependencyManagement>.
            .filter(|d| {
                d.scope != "test"
                    && !d.group_id.is_empty()
                    && !d.artifact_id.is_empty()
                    && !d.version.is_empty()
            })
            .map(|d| Dependency {
                ecosystem: Ecosystem::Maven,
                name: format!("{}:{}", d.group_id, d.artifact_id),
                version: d.version,
                direct: true,
                ..Default::default()
            })
            .collect())
    }
}

// --- gradle.lockfile -------------------------------------------------

pub struct GradleLockfile;

impl LockfileParser for GradleLockfile {
    fn filename(&self) -> &'static str {
        "gradle.lockfile"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Strip "=configurations" suffix.
            let coord = line.split_once('=').map(|(c, _)| c).unwrap_or(line);
            if coord == "empty" {
                continue;
            }
            // "group:artifact:version".
            let parts: Vec<&str> = coord.splitn(3, ':').collect();
            if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
                continue;
            }
            out.push(Dependency {
                ecosystem: Ecosystem::Maven,
                name: format!("{}:{}", parts[0], parts[1]),
                version: parts[2].to_string(),
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
    fn pom_skips_test_scope_and_incomplete() {
        let raw = br#"<project>
            <dependencies>
                <dependency>
                    <groupId>com.google.guava</groupId>
                    <artifactId>guava</artifactId>
                    <version>33.0.0-jre</version>
                </dependency>
                <dependency>
                    <groupId>junit</groupId>
                    <artifactId>junit</artifactId>
                    <version>4.13.2</version>
                    <scope>test</scope>
                </dependency>
            </dependencies>
        </project>"#;
        let deps = PomXml.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert!(deps[0].direct);
    }

    #[test]
    fn gradle_strips_configs() {
        let raw = b"# gradle lockfile\n\
                    com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath\n\
                    empty=annotationProcessor\n";
        let deps = GradleLockfile.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, "33.0.0-jre");
    }
}
