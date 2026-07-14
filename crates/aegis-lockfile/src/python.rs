//! Python lockfile parsers. Port of the PyPI section of
//! `lockfile_pip.go`. Four shapes, one ecosystem (`pypi`):
//! poetry.lock / uv.lock (TOML), Pipfile.lock (JSON), requirements.txt
//! (plain `name==version`).

use std::collections::HashMap;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::common::parse_toml_packages;
use crate::{DirectMap, LockfileParser, ParseError};

// --- poetry.lock / uv.lock (same [[package]] TOML shape) -------------

pub struct PoetryLock;
pub struct UvLock;

impl LockfileParser for PoetryLock {
    fn filename(&self) -> &'static str {
        "poetry.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        Ok(toml_pypi_deps(raw))
    }
}

impl LockfileParser for UvLock {
    fn filename(&self) -> &'static str {
        "uv.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        Ok(toml_pypi_deps(raw))
    }
}

fn toml_pypi_deps(raw: &[u8]) -> Vec<Dependency> {
    parse_toml_packages(raw)
        .into_iter()
        .map(|p| Dependency {
            ecosystem: Ecosystem::PyPI,
            name: p.name,
            version: p.version,
            // Poetry/uv encode category in metadata not parsed here;
            // treat all as transitive.
            direct: false,
            ..Default::default()
        })
        .collect()
}

// --- Pipfile.lock (JSON, default + develop) --------------------------

pub struct PipfileLock;

#[derive(Deserialize, Default)]
struct PipEntry {
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct PipfileLockDoc {
    #[serde(default)]
    default: HashMap<String, PipEntry>,
    #[serde(default)]
    develop: HashMap<String, PipEntry>,
}

impl LockfileParser for PipfileLock {
    fn filename(&self) -> &'static str {
        "Pipfile.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: PipfileLockDoc = serde_json::from_slice(raw)
            .map_err(|e| ParseError(format!("pipfile.lock decode: {e}")))?;
        let mut out = Vec::with_capacity(doc.default.len() + doc.develop.len());
        // pipenv puts user-declared deps in both [packages] and [dev].
        for section in [&doc.default, &doc.develop] {
            for (name, e) in section {
                let ver = e.version.strip_prefix("==").unwrap_or(&e.version);
                if ver.is_empty() {
                    continue;
                }
                out.push(Dependency {
                    ecosystem: Ecosystem::PyPI,
                    name: name.clone(),
                    version: ver.to_string(),
                    direct: true,
                    ..Default::default()
                });
            }
        }
        Ok(out)
    }
}

// --- requirements.txt (plain name==version) --------------------------

pub struct RequirementsTxt;

impl LockfileParser for RequirementsTxt {
    fn filename(&self) -> &'static str {
        "requirements.txt"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        Ok(parse_requirements_txt(raw))
    }
}

/// PEP 508 name charset: `^[A-Za-z0-9._-]+$`.
fn valid_py_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// PEP 440 version charset: `^[A-Za-z0-9._!+*-]+$`.
fn valid_py_version(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'!' | b'+' | b'*' | b'-')
        })
}

fn parse_requirements_txt(raw: &[u8]) -> Vec<Dependency> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();

    for line in text.lines() {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip inline comments (" #").
        if let Some(idx) = line.find(" #") {
            line = line[..idx].trim();
        }
        // Skip include directives / editable installs / options.
        if line.starts_with('-') {
            continue;
        }
        // Must be pinned with `==` — other PEP 440 operators don't give
        // a single version to look up.
        let Some((before, after)) = line.split_once("==") else {
            continue;
        };
        let mut name = before.trim();
        // Trim PEP 508 extras: requests[security]==2.31.0.
        if let Some(br) = name.find('[') {
            name = &name[..br];
        }
        let mut ver = after.trim();
        // Trim env markers / hashes: "foo==1.0 ; python_version …" / "--hash=…".
        if let Some(sc) = ver.find([' ', ';']) {
            ver = ver[..sc].trim();
        }
        if name.is_empty() || ver.is_empty() {
            continue;
        }
        // Reject control chars / embedded NUL / trailing junk.
        if !valid_py_name(name) || !valid_py_version(ver) {
            continue;
        }
        out.push(Dependency {
            ecosystem: Ecosystem::PyPI,
            name: name.to_string(),
            version: ver.to_string(),
            direct: true, // requirements.txt entries are all user-declared
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poetry_toml_all_transitive() {
        let raw = br#"
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"
"#;
        let deps = PoetryLock.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .all(|d| !d.direct && d.ecosystem == Ecosystem::PyPI));
    }

    #[test]
    fn pipfile_strips_double_equals_and_marks_direct() {
        let raw = br#"{
            "default": { "flask": { "version": "==3.0.0" } },
            "develop": { "pytest": { "version": "==8.0.0" } }
        }"#;
        let mut deps = PipfileLock.parse(raw, &DirectMap::new()).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "flask");
        assert_eq!(deps[0].version, "3.0.0");
        assert!(deps.iter().all(|d| d.direct));
    }

    #[test]
    fn requirements_handles_extras_markers_and_junk() {
        let raw = b"# comment\n\
                    requests[security]==2.31.0\n\
                    flask==3.0.0 ; python_version >= \"3.8\"\n\
                    unpinned-package\n\
                    -r other.txt\n\
                    bad==1.0\x00evil\n";
        let deps = parse_requirements_txt(raw);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["requests", "flask"]);
        assert_eq!(deps[0].version, "2.31.0");
        assert_eq!(deps[1].version, "3.0.0");
    }
}
