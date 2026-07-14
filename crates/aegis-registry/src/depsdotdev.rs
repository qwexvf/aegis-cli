//! deps.dev (Google) adapter. Port of `internal/infra/depsdotdev/client.go`.
//!
//! Two capabilities off the GetVersion endpoint:
//!  - **package health**: `isDeprecated` + `deprecatedReason`;
//!  - **advisories**: `advisoryKeys` → per-advisory detail (an alternate
//!    `VulnLookup` source).
//!
//! Supported systems: npm, pypi, cargo, go, maven, nuget. Others skip.

use std::collections::HashMap;

use aegis_domain::{Advisory, AdvisoryQuery, Ecosystem, Severity};
use aegis_net::HttpClient;
use serde::Deserialize;

pub const DEFAULT_BASE_URL: &str = "https://api.deps.dev";

pub struct DepsDevClient {
    base_url: String,
}

impl Default for DepsDevClient {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

/// Package-health signals from deps.dev. Mirrors the deprecation fields
/// of the GetVersion response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageHealth {
    pub is_deprecated: bool,
    pub deprecated_reason: String,
}

#[derive(Deserialize, Default)]
struct AdvisoryKey {
    #[serde(default)]
    id: String,
}

#[derive(Deserialize, Default)]
struct VersionResp {
    #[serde(rename = "advisoryKeys", default)]
    advisory_keys: Vec<AdvisoryKey>,
    #[serde(rename = "isDeprecated", default)]
    is_deprecated: bool,
    #[serde(rename = "deprecatedReason", default)]
    deprecated_reason: String,
}

#[derive(Deserialize, Default)]
struct AliasId {
    #[serde(default)]
    id: String,
}
#[derive(Deserialize, Default)]
struct AdvisoryInner {
    #[serde(default)]
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    aliases: Vec<AliasId>,
}
#[derive(Deserialize, Default)]
struct AdvisoryResp {
    #[serde(default)]
    advisory: AdvisoryInner,
}

impl DepsDevClient {
    pub fn new(base_url: &str) -> Self {
        DepsDevClient {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Deprecation health for one version, or None on any failure.
    pub fn fetch_health(
        &self,
        http: &dyn HttpClient,
        eco: Ecosystem,
        name: &str,
        version: &str,
    ) -> Option<PackageHealth> {
        let vr = self.fetch_version(http, eco, name, version)?;
        Some(PackageHealth {
            is_deprecated: vr.is_deprecated,
            deprecated_reason: vr.deprecated_reason,
        })
    }

    /// Advisories for a set of queries, keyed by [`AdvisoryQuery::key`].
    /// An alternate `VulnLookup` source. Mirrors `Client.Lookup`.
    pub fn lookup(
        &self,
        http: &dyn HttpClient,
        queries: &[AdvisoryQuery],
    ) -> HashMap<String, Vec<Advisory>> {
        let mut out: HashMap<String, Vec<Advisory>> = HashMap::new();
        for q in queries {
            out.insert(q.key(), Vec::new());
        }
        for q in queries {
            let Some(vr) = self.fetch_version(http, q.ecosystem, &q.name, &q.version) else {
                continue;
            };
            let mut advs = Vec::new();
            for key in &vr.advisory_keys {
                match self.fetch_one_advisory(http, &key.id) {
                    Some(adv) => advs.push(adv),
                    None => advs.push(Advisory {
                        id: key.id.clone(),
                        severity: Severity::Info,
                        summary: "(failed to fetch advisory details)".to_string(),
                        source: "deps.dev".to_string(),
                        ..Default::default()
                    }),
                }
            }
            out.insert(q.key(), advs);
        }
        out
    }

    fn fetch_version(
        &self,
        http: &dyn HttpClient,
        eco: Ecosystem,
        name: &str,
        version: &str,
    ) -> Option<VersionResp> {
        let system = deps_system(eco)?;
        let url = format!(
            "{}/v3alpha/systems/{}/packages/{}/versions/{}",
            self.base_url, system, name, version
        );
        let resp = http.get(&url, &[("Accept", "application/json")]).ok()?;
        if resp.status == 404 {
            return Some(VersionResp::default());
        }
        if !resp.is_ok() {
            return None;
        }
        serde_json::from_slice(&resp.body).ok()
    }

    fn fetch_one_advisory(&self, http: &dyn HttpClient, id: &str) -> Option<Advisory> {
        let url = format!("{}/v3alpha/advisories/{}", self.base_url, id);
        let resp = http.get(&url, &[("Accept", "application/json")]).ok()?;
        if !resp.is_ok() {
            return None;
        }
        let doc: AdvisoryResp = serde_json::from_slice(&resp.body).ok()?;
        Some(Advisory {
            id: id.to_string(),
            aliases: doc.advisory.aliases.into_iter().map(|a| a.id).collect(),
            severity: severity_from_deps_dev(&doc.advisory.severity),
            summary: doc.advisory.title,
            url: doc.advisory.url,
            source: "deps.dev".to_string(),
            ..Default::default()
        })
    }
}

/// Map the domain Ecosystem onto deps.dev's system vocabulary. None for
/// unsupported ecosystems. Mirrors `depsSystem`.
fn deps_system(eco: Ecosystem) -> Option<&'static str> {
    Some(match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::Crates => "cargo",
        Ecosystem::Go => "go",
        Ecosystem::Maven => "maven",
        Ecosystem::NuGet => "nuget",
        _ => return None,
    })
}

fn severity_from_deps_dev(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MODERATE" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    fn version_url(base: &str, sys: &str, name: &str, ver: &str) -> String {
        format!("{base}/v3alpha/systems/{sys}/packages/{name}/versions/{ver}")
    }

    #[test]
    fn fetch_health_reads_deprecation() {
        let base = "https://d.test";
        let body =
            r#"{"isDeprecated":true,"deprecatedReason":"use foo instead","advisoryKeys":[]}"#;
        let http = MockHttpClient::new().with(
            &version_url(base, "npm", "request", "2.88.2"),
            200,
            body.as_bytes().to_vec(),
        );
        let health = DepsDevClient::new(base)
            .fetch_health(&http, Ecosystem::Npm, "request", "2.88.2")
            .unwrap();
        assert!(health.is_deprecated);
        assert_eq!(health.deprecated_reason, "use foo instead");
    }

    #[test]
    fn unsupported_system_yields_no_health_and_no_call() {
        let http = MockHttpClient::new();
        let health = DepsDevClient::new("https://d.test").fetch_health(
            &http,
            Ecosystem::RubyGems,
            "rails",
            "7.1.0",
        );
        assert!(health.is_none());
        assert_eq!(http.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn lookup_resolves_advisory_keys() {
        let base = "https://d.test";
        let ver_body = r#"{"advisoryKeys":[{"id":"GHSA-aaaa"}]}"#;
        let adv_body = r#"{"advisory":{"url":"https://x","title":"bad bug","severity":"HIGH","aliases":[{"id":"CVE-2020-1"}]}}"#;
        let http = MockHttpClient::new()
            .with(
                &version_url(base, "cargo", "openssl", "0.10.0"),
                200,
                ver_body.as_bytes().to_vec(),
            )
            .with(
                &format!("{base}/v3alpha/advisories/GHSA-aaaa"),
                200,
                adv_body.as_bytes().to_vec(),
            );

        let queries = vec![AdvisoryQuery {
            ecosystem: Ecosystem::Crates,
            name: "openssl".into(),
            version: "0.10.0".into(),
        }];
        let result = DepsDevClient::new(base).lookup(&http, &queries);
        let advs = &result["crates/openssl@0.10.0"];
        assert_eq!(advs.len(), 1);
        assert_eq!(advs[0].severity, Severity::High);
        assert_eq!(advs[0].summary, "bad bug");
        assert_eq!(advs[0].aliases, vec!["CVE-2020-1"]);
    }
}
