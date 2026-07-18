//! CycloneDX 1.5 BOM emitter. Port of `sbomcdx/cyclonedx.go`.
//!
//! Pure transformation from a dependency list to a CycloneDX JSON document —
//! no I/O, no clock. The caller passes a timestamp + serial number so two runs
//! over the same input produce byte-identical output. Components carry PURL,
//! scope, and (when present) an integrity hash; the `dependencies` graph is
//! built from each dep's `depends_on`.

use std::collections::BTreeMap;

use aegis_domain::{Advisory, Dependency};
use serde::Serialize;

use crate::purl::purl;

/// Advisories keyed by [`Dependency::versioned_key`] — the shape the SBOM
/// emitters accept for the `vulnerabilities` section. Empty = none known.
pub type AdvisoryMap = BTreeMap<String, Vec<Advisory>>;

/// Controls one BOM build. `timestamp` and `serial_number` are explicit for
/// determinism — the crate never reads the clock or generates randomness.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Stamped on the tool record. e.g. the aegis CLI version.
    pub aegis_version: String,
    /// Root component name. Falls back to "project" when empty.
    pub project: String,
    /// RFC3339 timestamp for metadata.timestamp.
    pub timestamp: String,
    /// `urn:uuid:...` serial number for this BOM.
    pub serial_number: String,
}

/// Build a CycloneDX 1.5 BOM as a pretty-printed JSON string (no advisories).
pub fn build_json(deps: &[Dependency], opts: &Options) -> String {
    build_json_adv(deps, &AdvisoryMap::new(), opts)
}

/// Build a CycloneDX 1.5 BOM as JSON, including a `vulnerabilities` section
/// for any advisories keyed to a dependency's [`Dependency::versioned_key`].
pub fn build_json_adv(deps: &[Dependency], advisories: &AdvisoryMap, opts: &Options) -> String {
    serde_json::to_string_pretty(&build(deps, advisories, opts)).unwrap_or_default()
}

/// Build the typed BOM document.
pub fn build(deps: &[Dependency], advisories: &AdvisoryMap, opts: &Options) -> Bom {
    let root_name = if opts.project.is_empty() {
        "project".to_string()
    } else {
        opts.project.clone()
    };
    let root_ref = format!("aegis:root:{root_name}");

    let components: Vec<Component> = deps.iter().map(component_from_dep).collect();
    let dependencies = dependencies_from_deps(deps, &root_ref);
    let vulnerabilities = vulnerabilities_from(deps, advisories);

    Bom {
        schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
        bom_format: "CycloneDX",
        spec_version: "1.5",
        serial_number: opts.serial_number.clone(),
        version: 1,
        metadata: Metadata {
            timestamp: opts.timestamp.clone(),
            tools: Tools {
                components: vec![ToolComponent {
                    component_type: "application",
                    name: "aegis-cli",
                    version: opts.aegis_version.clone(),
                }],
            },
            component: RootComponent {
                bom_ref: root_ref,
                component_type: "application",
                name: root_name,
            },
        },
        components,
        dependencies,
        vulnerabilities,
    }
}

/// Build the `vulnerabilities` array: one entry per (dependency, advisory),
/// `affects` pointing at the component's bom-ref. Deps are visited in order
/// and each dep's advisories sorted by id for deterministic output.
fn vulnerabilities_from(deps: &[Dependency], advisories: &AdvisoryMap) -> Vec<Vulnerability> {
    let mut out = Vec::new();
    for d in deps {
        let Some(advs) = advisories.get(&d.versioned_key()) else {
            continue;
        };
        let mut advs: Vec<&Advisory> = advs.iter().collect();
        advs.sort_by(|a, b| a.id.cmp(&b.id));
        let bom_ref = bom_ref_for(d);
        for adv in advs {
            out.push(Vulnerability {
                id: adv.id.clone(),
                source: (!adv.source.is_empty() || !adv.url.is_empty()).then(|| VulnSource {
                    name: adv.source.clone(),
                    url: adv.url.clone(),
                }),
                ratings: vec![Rating {
                    severity: adv.severity.as_str().to_ascii_lowercase(),
                }],
                description: adv.summary.clone(),
                affects: vec![Affects {
                    reference: bom_ref.clone(),
                }],
            });
        }
    }
    out
}

/// Stable bom-ref for a dep: PURL preferred, `eco:name@version` fallback.
fn bom_ref_for(d: &Dependency) -> String {
    let p = purl(d);
    if p.is_empty() {
        format!("{}:{}@{}", d.ecosystem.as_str(), d.name, d.version)
    } else {
        p
    }
}

fn component_from_dep(d: &Dependency) -> Component {
    let p = purl(d);
    Component {
        bom_ref: bom_ref_for(d),
        component_type: "library",
        name: d.name.clone(),
        version: d.version.clone(),
        purl: (!p.is_empty()).then_some(p),
        scope: if d.direct { "required" } else { "optional" },
        hashes: hash_from_integrity(&d.integrity).map(|h| vec![h]),
        // A resolved SPDX license → `licenses: [{license: {id}}]`; omitted
        // when unknown (CycloneDX has no NOASSERTION requirement).
        licenses: (!d.license.is_empty()).then(|| {
            vec![LicenseChoice {
                license: LicenseId {
                    id: d.license.clone(),
                },
            }]
        }),
    }
}

/// Build the `dependencies` graph. Root dependsOn all direct deps; each dep
/// lists its resolved children (from `depends_on`, keyed by versioned_key).
fn dependencies_from_deps(deps: &[Dependency], root_ref: &str) -> Vec<DependencyNode> {
    let key_to_ref: std::collections::HashMap<String, String> = deps
        .iter()
        .map(|d| (d.versioned_key(), bom_ref_for(d)))
        .collect();

    let mut root_deps: Vec<String> = deps.iter().filter(|d| d.direct).map(bom_ref_for).collect();
    root_deps.sort();

    let mut out = vec![DependencyNode {
        reference: root_ref.to_string(),
        depends_on: root_deps,
    }];

    for d in deps {
        let mut children: Vec<String> = d
            .depends_on
            .iter()
            .filter_map(|k| key_to_ref.get(k).cloned())
            .collect();
        children.sort();
        out.push(DependencyNode {
            reference: bom_ref_for(d),
            depends_on: children,
        });
    }
    out
}

/// Decode an npm-style `sha512-<base64>` integrity string into a CycloneDX
/// hash (hex-encoded digest). `None` for empty / over-long / unknown-algo /
/// undecodable input — the BOM stays valid, just without a hash there.
fn hash_from_integrity(integrity: &str) -> Option<Hash> {
    const MAX_LEN: usize = 512;
    if integrity.is_empty() || integrity.len() > MAX_LEN {
        return None;
    }
    let (algo, b64) = integrity.split_once('-')?;
    let alg = match algo.to_ascii_lowercase().as_str() {
        "sha512" => "SHA-512",
        "sha384" => "SHA-384",
        "sha256" => "SHA-256",
        "sha1" => "SHA-1",
        _ => return None,
    };
    let raw = base64_decode(b64)?;
    Some(Hash {
        alg,
        content: hex_encode(&raw),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Minimal standard-base64 decoder (RFC 4648, with `=` padding). Returns None
/// on any invalid character or malformed length.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let n = chunk.len();
        if n < 2 {
            return None;
        }
        for (i, &c) in chunk.iter().enumerate() {
            buf[i] = val(c)?;
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if n >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if n == 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(out)
}

// --- CycloneDX 1.5 JSON schema (subset) -------------------------------------

#[derive(Serialize)]
pub struct Bom {
    #[serde(rename = "$schema")]
    schema: &'static str,
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    #[serde(rename = "serialNumber", skip_serializing_if = "String::is_empty")]
    serial_number: String,
    version: u32,
    metadata: Metadata,
    components: Vec<Component>,
    dependencies: Vec<DependencyNode>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<Vulnerability>,
}

/// A CycloneDX 1.5 `vulnerabilities[]` entry.
#[derive(Serialize)]
struct Vulnerability {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<VulnSource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ratings: Vec<Rating>,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    affects: Vec<Affects>,
}

#[derive(Serialize)]
struct VulnSource {
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    url: String,
}

#[derive(Serialize)]
struct Rating {
    severity: String,
}

#[derive(Serialize)]
struct Affects {
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Serialize)]
struct Metadata {
    #[serde(skip_serializing_if = "String::is_empty")]
    timestamp: String,
    tools: Tools,
    component: RootComponent,
}

#[derive(Serialize)]
struct Tools {
    components: Vec<ToolComponent>,
}

#[derive(Serialize)]
struct ToolComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
}

#[derive(Serialize)]
struct RootComponent {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    component_type: &'static str,
    name: String,
}

#[derive(Serialize)]
struct Component {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    component_type: &'static str,
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<Hash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<LicenseChoice>>,
}

#[derive(Serialize)]
struct Hash {
    alg: &'static str,
    content: String,
}

/// CycloneDX `licenses[]` entry: `{ "license": { "id": "MIT" } }`.
#[derive(Serialize)]
struct LicenseChoice {
    license: LicenseId,
}

#[derive(Serialize)]
struct LicenseId {
    id: String,
}

#[derive(Serialize)]
struct DependencyNode {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
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
            serial_number: "urn:uuid:11111111-1111-4111-8111-111111111111".into(),
        }
    }

    #[test]
    fn base64_decode_roundtrip_known() {
        // "sha512-" of a known digest: decode base64 → hex.
        // base64("hi") = "aGk=" → bytes [0x68,0x69] → hex "6869"
        assert_eq!(base64_decode("aGk=").unwrap(), vec![0x68, 0x69]);
        assert_eq!(hex_encode(&[0x68, 0x69]), "6869");
    }

    #[test]
    fn integrity_becomes_hex_hash() {
        let mut d = dep("x", "1.0.0", true);
        d.integrity = "sha512-aGk=".into(); // decodes to "hi" → 6869
        let c = component_from_dep(&d);
        let h = c.hashes.unwrap();
        assert_eq!(h[0].alg, "SHA-512");
        assert_eq!(h[0].content, "6869");
    }

    #[test]
    fn bad_integrity_yields_no_hash() {
        for bad in ["", "notalgo", "md5-aGk=", "sha512-!!!!"] {
            assert!(hash_from_integrity(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn license_renders_as_spdx_id_choice() {
        let mut d = dep("lodash", "4.17.21", true);
        d.license = "MIT".into();
        let json = build_json(&[d], &opts());
        let v: Value = serde_json::from_str(&json).unwrap();
        let comp = &v["components"][0];
        assert_eq!(comp["licenses"][0]["license"]["id"], "MIT");
    }

    #[test]
    fn absent_license_omits_field() {
        // No license → the `licenses` key is skipped entirely (valid CycloneDX).
        let json = build_json(&[dep("x", "1.0.0", true)], &opts());
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["components"][0].get("licenses").is_none());
    }

    #[test]
    fn no_advisories_omits_vulnerabilities() {
        let json = build_json(&[dep("lodash", "4.17.21", true)], &opts());
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("vulnerabilities").is_none());
    }

    #[test]
    fn advisories_emit_vulnerabilities_with_affects() {
        let d = dep("lodash", "4.17.4", true);
        let adv = aegis_domain::Advisory {
            id: "CVE-2019-10744".into(),
            severity: aegis_domain::Severity::Critical,
            summary: "prototype pollution".into(),
            url: "https://osv.dev/CVE-2019-10744".into(),
            source: "osv".into(),
            ..Default::default()
        };
        let mut map = AdvisoryMap::new();
        map.insert(d.versioned_key(), vec![adv]);

        let json = build_json_adv(std::slice::from_ref(&d), &map, &opts());
        let v: Value = serde_json::from_str(&json).unwrap();
        let vuln = &v["vulnerabilities"][0];
        assert_eq!(vuln["id"], "CVE-2019-10744");
        assert_eq!(vuln["ratings"][0]["severity"], "critical");
        assert_eq!(vuln["source"]["name"], "osv");
        // affects points at the component's bom-ref (its purl).
        assert_eq!(vuln["affects"][0]["ref"], bom_ref_for(&d));
    }

    #[test]
    fn build_shape_and_graph() {
        let deps = vec![dep("lodash", "4.17.21", true), {
            let mut d = dep("ms", "2.1.3", false);
            d.depends_on = vec![]; // leaf
            d
        }];
        // lodash depends on ms
        let mut deps = deps;
        deps[0].depends_on = vec!["npm/ms@2.1.3".into()];

        let json = build_json(&deps, &opts());
        let v: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert_eq!(
            v["serialNumber"],
            "urn:uuid:11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(v["metadata"]["component"]["name"], "myapp");
        assert_eq!(v["metadata"]["component"]["bom-ref"], "aegis:root:myapp");

        // two components, lodash carries a purl + required scope
        let comps = v["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2);
        let lodash = comps.iter().find(|c| c["name"] == "lodash").unwrap();
        assert_eq!(lodash["purl"], "pkg:npm/lodash@4.17.21");
        assert_eq!(lodash["scope"], "required");

        // dependency graph: root dependsOn lodash (the direct dep);
        // lodash dependsOn ms.
        let graph = v["dependencies"].as_array().unwrap();
        let root = graph
            .iter()
            .find(|d| d["ref"] == "aegis:root:myapp")
            .unwrap();
        assert_eq!(root["dependsOn"][0], "pkg:npm/lodash@4.17.21");
        let lo = graph
            .iter()
            .find(|d| d["ref"] == "pkg:npm/lodash@4.17.21")
            .unwrap();
        assert_eq!(lo["dependsOn"][0], "pkg:npm/ms@2.1.3");
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let deps = vec![dep("a", "1.0.0", true)];
        assert_eq!(build_json(&deps, &opts()), build_json(&deps, &opts()));
    }
}
