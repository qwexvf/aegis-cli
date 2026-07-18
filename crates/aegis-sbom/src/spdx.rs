//! SPDX 2.3 JSON emitter. Port of `sbomcdx/spdx.go`.
//!
//! Pure transform from a dependency list to an SPDX document. Deterministic:
//! the caller supplies the timestamp + serial (used as the namespace UUID).
//! A dep's `license` (resolved by `sbom --online`) fills `licenseConcluded`
//! / `licenseDeclared`; an empty license emits `NOASSERTION` so the document
//! stays spec-valid. Advisory fields aren't on `Dependency` yet.

use aegis_domain::Dependency;
use serde::Serialize;

use crate::purl::purl;

/// Options for one SPDX build (timestamp + serial passed for determinism).
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub aegis_version: String,
    pub project: String,
    /// RFC3339 timestamp for creationInfo.created.
    pub timestamp: String,
    /// `urn:uuid:...` serial; its UUID part forms the documentNamespace.
    pub serial_number: String,
}

/// Build an SPDX 2.3 document as a pretty-printed JSON string.
pub fn build_json(deps: &[Dependency], opts: &Options) -> String {
    serde_json::to_string_pretty(&build(deps, opts)).unwrap_or_default()
}

/// Build the typed SPDX document.
pub fn build(deps: &[Dependency], opts: &Options) -> Document {
    let root_name = if opts.project.is_empty() {
        "project".to_string()
    } else {
        opts.project.clone()
    };
    let uuid_part = opts
        .serial_number
        .strip_prefix("urn:uuid:")
        .unwrap_or(&opts.serial_number);
    let root_id = format!("SPDXRef-{}", sanitize_id(&format!("Package-{root_name}")));
    let namespace = format!(
        "https://aegis-cli.dev/sbom/{}/{}",
        percent_escape(&root_name),
        uuid_part
    );

    let mut packages = vec![Package {
        spdxid: root_id.clone(),
        name: root_name.clone(),
        version_info: "NOASSERTION".into(),
        download_location: "NOASSERTION".into(),
        files_analyzed: false,
        external_refs: Vec::new(),
        license_concluded: "NOASSERTION".into(),
        license_declared: "NOASSERTION".into(),
        copyright_text: "NOASSERTION".into(),
    }];
    let mut relationships = vec![Relationship {
        spdx_element_id: "SPDXRef-DOCUMENT".into(),
        relationship_type: "DESCRIBES".into(),
        related_spdx_element: root_id.clone(),
    }];

    for d in deps {
        let pkg_id = format!("SPDXRef-{}", package_id(d));
        relationships.push(Relationship {
            spdx_element_id: root_id.clone(),
            relationship_type: if d.direct {
                "DEPENDS_ON"
            } else {
                "DYNAMIC_LINK"
            }
            .into(),
            related_spdx_element: pkg_id.clone(),
        });

        let mut external_refs = Vec::new();
        let p = purl(d);
        if !p.is_empty() {
            external_refs.push(ExternalRef {
                reference_category: "PACKAGE-MANAGER",
                reference_type: "purl",
                reference_locator: p,
            });
        }
        // A resolved license populates both concluded and declared; empty
        // stays NOASSERTION so the document remains spec-valid.
        let license = if d.license.is_empty() {
            "NOASSERTION".to_string()
        } else {
            d.license.clone()
        };
        packages.push(Package {
            spdxid: pkg_id,
            name: d.name.clone(),
            version_info: d.version.clone(),
            download_location: "NOASSERTION".into(),
            files_analyzed: false,
            external_refs,
            license_concluded: license.clone(),
            license_declared: license,
            copyright_text: "NOASSERTION".into(),
        });
    }

    Document {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdxid: "SPDXRef-DOCUMENT",
        name: root_name,
        document_namespace: namespace,
        creation_info: CreationInfo {
            created: opts.timestamp.clone(),
            creators: vec![format!("Tool: aegis-cli-{}", opts.aegis_version)],
        },
        packages,
        relationships,
    }
}

/// SPDX 2.3 §2.2: identifiers allow only `[a-zA-Z0-9-.]`; replace the rest.
fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn package_id(d: &Dependency) -> String {
    sanitize_id(&format!(
        "Package-{}-{}-{}",
        d.ecosystem.as_str(),
        d.name,
        d.version
    ))
}

/// Minimal path percent-escape for the namespace URI segment.
fn percent_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// --- SPDX 2.3 JSON schema (subset) ------------------------------------------

#[derive(Serialize)]
pub struct Document {
    #[serde(rename = "spdxVersion")]
    spdx_version: &'static str,
    #[serde(rename = "dataLicense")]
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdxid: &'static str,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    #[serde(rename = "creationInfo")]
    creation_info: CreationInfo,
    packages: Vec<Package>,
    relationships: Vec<Relationship>,
}

#[derive(Serialize)]
struct CreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Serialize)]
struct Package {
    #[serde(rename = "SPDXID")]
    spdxid: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: String,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(rename = "externalRefs", skip_serializing_if = "Vec::is_empty")]
    external_refs: Vec<ExternalRef>,
    #[serde(rename = "licenseConcluded")]
    license_concluded: String,
    #[serde(rename = "licenseDeclared")]
    license_declared: String,
    #[serde(rename = "copyrightText")]
    copyright_text: String,
}

#[derive(Serialize)]
struct ExternalRef {
    #[serde(rename = "referenceCategory")]
    reference_category: &'static str,
    #[serde(rename = "referenceType")]
    reference_type: &'static str,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

#[derive(Serialize)]
struct Relationship {
    #[serde(rename = "spdxElementId")]
    spdx_element_id: String,
    #[serde(rename = "relationshipType")]
    relationship_type: String,
    #[serde(rename = "relatedSpdxElement")]
    related_spdx_element: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_domain::Ecosystem;
    use serde_json::Value;

    fn dep(name: &str, version: &str, direct: bool) -> Dependency {
        Dependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            direct,
            ..Default::default()
        }
    }

    fn opts() -> Options {
        Options {
            aegis_version: "0.1.0".into(),
            project: "myapp".into(),
            timestamp: "2026-07-16T00:00:00Z".into(),
            serial_number: "urn:uuid:22222222-2222-4222-8222-222222222222".into(),
        }
    }

    #[test]
    fn document_shape_and_relationships() {
        let deps = vec![dep("lodash", "4.17.21", true), dep("ms", "2.1.3", false)];
        let json = build_json(&deps, &opts());
        let v: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["dataLicense"], "CC0-1.0");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(v["documentNamespace"]
            .as_str()
            .unwrap()
            .contains("22222222-2222-4222-8222-222222222222"));

        // root + 2 deps = 3 packages
        assert_eq!(v["packages"].as_array().unwrap().len(), 3);

        // lodash carries a purl externalRef
        let lodash = v["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "lodash")
            .unwrap();
        assert_eq!(
            lodash["externalRefs"][0]["referenceLocator"],
            "pkg:npm/lodash@4.17.21"
        );

        // relationships: DOCUMENT DESCRIBES root; root DEPENDS_ON lodash (direct),
        // DYNAMIC_LINK ms (transitive).
        let rels = v["relationships"].as_array().unwrap();
        assert!(rels.iter().any(|r| r["relationshipType"] == "DESCRIBES"));
        assert!(rels.iter().any(|r| r["relationshipType"] == "DEPENDS_ON"));
        assert!(rels.iter().any(|r| r["relationshipType"] == "DYNAMIC_LINK"));
    }

    #[test]
    fn spdx_id_sanitized() {
        // scoped name has chars that must be replaced in the SPDXID
        let d = dep("@scope/pkg", "1.0.0", true);
        assert_eq!(package_id(&d), "Package-npm--scope-pkg-1.0.0");
    }

    #[test]
    fn license_populates_concluded_and_declared() {
        let mut d = dep("lodash", "4.17.21", true);
        d.license = "MIT".into();
        let v: Value = serde_json::from_str(&build_json(&[d], &opts())).unwrap();
        let lodash = v["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "lodash")
            .unwrap();
        assert_eq!(lodash["licenseConcluded"], "MIT");
        assert_eq!(lodash["licenseDeclared"], "MIT");
    }

    #[test]
    fn absent_license_stays_noassertion() {
        let v: Value =
            serde_json::from_str(&build_json(&[dep("x", "1.0.0", true)], &opts())).unwrap();
        let x = v["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "x")
            .unwrap();
        assert_eq!(x["licenseConcluded"], "NOASSERTION");
        assert_eq!(x["licenseDeclared"], "NOASSERTION");
    }
}
