//! Swift PM `Package.resolved` parser. Port of `lockfile_swift.go`.
//!
//! v1 and v2 schemas. OSV "SwiftURL" keys on the repository URL, so the
//! URL is stored as the name. Revision-only pins keep the revision hash
//! as the version so the VCS heuristic can flag them.

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct PackageResolved;

#[derive(Deserialize, Default)]
struct State {
    #[serde(default)]
    version: String,
    #[serde(default)]
    revision: String,
}

#[derive(Deserialize, Default)]
struct PinV2 {
    #[serde(default)]
    location: String,
    #[serde(default)]
    state: State,
}

#[derive(Deserialize, Default)]
struct PinV1 {
    #[serde(rename = "repositoryURL", default)]
    repository_url: String,
    #[serde(default)]
    state: State,
}

#[derive(Deserialize, Default)]
struct DocV2 {
    #[serde(default)]
    pins: Vec<PinV2>,
}

#[derive(Deserialize, Default)]
struct ObjectV1 {
    #[serde(default)]
    pins: Vec<PinV1>,
}

#[derive(Deserialize, Default)]
struct DocV1 {
    #[serde(default)]
    object: ObjectV1,
}

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    version: i64,
}

impl LockfileParser for PackageResolved {
    fn filename(&self) -> &'static str {
        "Package.resolved"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::SwiftPM
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let env: Envelope = serde_json::from_slice(raw)
            .map_err(|e| ParseError(format!("package.resolved: {e}")))?;
        if env.version == 2 {
            parse_v2(raw)
        } else {
            // v1 is the fallback for unrecognised versions too.
            parse_v1(raw)
        }
    }
}

fn mk(url: String, state: &State) -> Option<Dependency> {
    if url.is_empty() {
        return None;
    }
    let ver = if !state.version.is_empty() {
        state.version.clone()
    } else {
        state.revision.clone() // branch/commit pin — no semver
    };
    if ver.is_empty() {
        return None;
    }
    Some(Dependency {
        ecosystem: Ecosystem::SwiftPM,
        name: url, // OSV SwiftURL uses repo URL as identifier
        version: ver,
        ..Default::default()
    })
}

fn parse_v2(raw: &[u8]) -> Result<Vec<Dependency>, ParseError> {
    let doc: DocV2 =
        serde_json::from_slice(raw).map_err(|e| ParseError(format!("package.resolved v2: {e}")))?;
    Ok(doc
        .pins
        .into_iter()
        .filter_map(|p| mk(p.location, &p.state))
        .collect())
}

fn parse_v1(raw: &[u8]) -> Result<Vec<Dependency>, ParseError> {
    let doc: DocV1 =
        serde_json::from_slice(raw).map_err(|e| ParseError(format!("package.resolved v1: {e}")))?;
    Ok(doc
        .object
        .pins
        .into_iter()
        .filter_map(|p| mk(p.repository_url, &p.state))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_uses_location_and_revision_fallback() {
        let raw = br#"{
            "version": 2,
            "pins": [
                { "location": "https://github.com/apple/swift-nio",
                  "state": { "version": "2.62.0" } },
                { "location": "https://github.com/x/y",
                  "state": { "revision": "deadbeef" } }
            ]
        }"#;
        let deps = PackageResolved.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "https://github.com/apple/swift-nio");
        assert_eq!(deps[0].version, "2.62.0");
        assert_eq!(deps[1].version, "deadbeef");
    }

    #[test]
    fn v1_object_pins() {
        let raw = br#"{
            "version": 1,
            "object": { "pins": [
                { "repositoryURL": "https://github.com/a/b",
                  "state": { "version": "1.0.0" } }
            ] }
        }"#;
        let deps = PackageResolved.parse(raw, &DirectMap::new()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "https://github.com/a/b");
    }
}
