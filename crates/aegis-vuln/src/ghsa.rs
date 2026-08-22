//! GHSA lookup. Port of `internal/infra/ghsalookup/client.go`.
//!
//! Queries the GitHub Security Advisory database directly via the GitHub
//! GraphQL API (`securityVulnerabilities`). GitHub publishes advisories
//! hours before OSV's hourly sync picks them up, and carries GHSA records
//! OSV hasn't indexed yet, so this runs alongside the OSV adapter.
//!
//! Auth is a GitHub personal access token (read from env by the caller,
//! passed in via [`GhsaClient::with_token`]). Without a token there are no
//! GHSA results — the unauthenticated GraphQL API rejects the call, so we
//! skip the network entirely. Network/parse failures degrade to an empty
//! result, never an error, matching the OSV/KEV adapters.

use std::collections::HashMap;

use aegis_domain::{Advisory, AdvisoryQuery, Ecosystem, Severity};
use aegis_net::HttpClient;
use serde::Deserialize;

/// GitHub GraphQL API root. Override for GitHub Enterprise / tests.
pub const DEFAULT_BASE_URL: &str = "https://api.github.com";

/// The `securityVulnerabilities` query. One package per call; `first: 100`
/// matches Go's `per_page=100`.
const GHSA_QUERY: &str = "\
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 100) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        permalink
        identifiers { type value }
      }
      firstPatchedVersion { identifier }
      vulnerableVersionRange
    }
  }
}";

pub struct GhsaClient {
    base_url: String,
    token: Option<String>,
}

impl Default for GhsaClient {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

impl GhsaClient {
    pub fn new(base_url: &str) -> Self {
        GhsaClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    /// Set the base URL (GitHub Enterprise host or a test server).
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim_end_matches('/').to_string();
        self
    }

    /// Set the GitHub personal access token. An empty token is treated as
    /// no token (i.e. no GHSA results).
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    /// Look up advisories for each query. Returns a map keyed by
    /// [`AdvisoryQuery::key`]; every input query gets an entry (empty vec =
    /// "looked up, none found"). Mirrors `Client.Lookup`.
    ///
    /// Queries are grouped by (ecosystem, package) so multiple versions of
    /// the same package share one API call, matching Go's `byPkg` batching.
    /// Without a token, or on any network/parse failure, the affected
    /// entries stay empty rather than erroring.
    pub fn lookup(
        &self,
        http: &dyn HttpClient,
        queries: &[AdvisoryQuery],
    ) -> HashMap<String, Vec<Advisory>> {
        let mut out: HashMap<String, Vec<Advisory>> = HashMap::new();
        for q in queries {
            out.insert(q.key(), Vec::new());
        }

        // No token → the GraphQL API rejects us; report no results.
        let Some(token) = self.token.as_deref().filter(|t| !t.is_empty()) else {
            return out;
        };

        // Group by (GitHub ecosystem, package name); drop ecosystems GHSA
        // doesn't cover. Sorted for deterministic order — matters because an
        // exhausted rate limit stops the batch mid-way (below).
        let mut by_pkg: HashMap<(&str, &str), Vec<&AdvisoryQuery>> = HashMap::new();
        for q in queries {
            if let Some(eco) = ghsa_ecosystem(q.ecosystem) {
                by_pkg.entry((eco, q.name.as_str())).or_default().push(q);
            }
        }
        let mut pkgs: Vec<((&str, &str), Vec<&AdvisoryQuery>)> = by_pkg.into_iter().collect();
        pkgs.sort_by(|a, b| a.0.cmp(&b.0));

        for ((eco, name), qs) in pkgs {
            // Non-fatal: a failed package fetch leaves those queries empty.
            let Some(fetch) = self.fetch_for_package(http, token, eco, name) else {
                continue;
            };
            for q in qs {
                out.insert(q.key(), fetch.advisories.clone());
            }
            // Rate budget spent: further calls in this batch would just 403.
            // Stop early — remaining packages stay empty (OSV still covers
            // them in the merge). Deterministic thanks to the sort above.
            if fetch.rate_remaining == Some(0) {
                break;
            }
        }
        out
    }

    /// One GraphQL call for a single package. `None` only on a transport
    /// failure; a non-2xx status yields an empty advisory list (so the batch
    /// can still read the rate-limit header and decide whether to stop).
    /// Mirrors `fetchForPackage` plus rate-limit awareness.
    fn fetch_for_package(
        &self,
        http: &dyn HttpClient,
        token: &str,
        eco: &str,
        name: &str,
    ) -> Option<PackageFetch> {
        let body = serde_json::to_vec(&serde_json::json!({
            "query": GHSA_QUERY,
            "variables": { "ecosystem": eco, "package": name },
        }))
        .ok()?;

        let auth = format!("Bearer {token}");
        let resp = http
            .post(
                &format!("{}/graphql", self.base_url),
                &body,
                &[
                    ("Authorization", auth.as_str()),
                    ("Content-Type", "application/json"),
                    ("Accept", "application/json"),
                    ("User-Agent", "aegis"),
                ],
            )
            .ok()?;
        // GitHub reports the remaining GraphQL budget on every response.
        let rate_remaining = resp
            .header("x-ratelimit-remaining")
            .and_then(|v| v.trim().parse::<u64>().ok());
        let advisories = if resp.is_ok() {
            parse_ghsa_response(&resp.body).unwrap_or_default()
        } else {
            Vec::new()
        };
        Some(PackageFetch {
            advisories,
            rate_remaining,
        })
    }
}

/// Outcome of one package fetch: the advisories (empty on a non-2xx status)
/// and GitHub's remaining rate-limit budget, when the header was present.
struct PackageFetch {
    advisories: Vec<Advisory>,
    rate_remaining: Option<u64>,
}

// --- wire types ------------------------------------------------------

#[derive(Deserialize, Default)]
struct Identifier {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize, Default)]
struct GhsaAdvisory {
    #[serde(rename = "ghsaId", default)]
    ghsa_id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    permalink: String,
    #[serde(default)]
    identifiers: Vec<Identifier>,
}

#[derive(Deserialize, Default)]
struct PatchedVersion {
    #[serde(default)]
    identifier: String,
}

#[derive(Deserialize, Default)]
struct VulnNode {
    #[serde(default)]
    advisory: GhsaAdvisory,
    #[serde(rename = "firstPatchedVersion", default)]
    first_patched_version: Option<PatchedVersion>,
}

#[derive(Deserialize, Default)]
struct SecurityVulns {
    #[serde(default)]
    nodes: Vec<VulnNode>,
}

#[derive(Deserialize, Default)]
struct GraphData {
    #[serde(rename = "securityVulnerabilities", default)]
    security_vulnerabilities: SecurityVulns,
}

#[derive(Deserialize, Default)]
struct GraphResp {
    #[serde(default)]
    data: GraphData,
}

// --- pure mapping (unit-testable) ------------------------------------

/// Decode a GitHub GraphQL `securityVulnerabilities` response into
/// [`Advisory`] values. Nodes without a GHSA id are skipped. Mirrors the
/// decode + `toAdvisory` path in the Go client.
pub fn parse_ghsa_response(raw: &[u8]) -> Result<Vec<Advisory>, String> {
    let resp: GraphResp = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    Ok(resp
        .data
        .security_vulnerabilities
        .nodes
        .iter()
        .filter(|n| !n.advisory.ghsa_id.is_empty())
        .map(node_to_advisory)
        .collect())
}

/// Map one `securityVulnerabilities` node onto an [`Advisory`]. CVE
/// identifiers become aliases; the first patched version becomes
/// `fixed_in`. Mirrors `toAdvisory`.
fn node_to_advisory(n: &VulnNode) -> Advisory {
    let a = &n.advisory;
    let aliases = a
        .identifiers
        .iter()
        .filter(|i| i.kind.eq_ignore_ascii_case("CVE") && !i.value.is_empty())
        .map(|i| i.value.clone())
        .collect();
    let fixed_in = n
        .first_patched_version
        .as_ref()
        .map(|p| p.identifier.clone())
        .unwrap_or_default();
    Advisory {
        id: a.ghsa_id.clone(),
        aliases,
        severity: parse_severity(&a.severity),
        summary: a.summary.clone(),
        url: a.permalink.clone(),
        source: "ghsa".to_string(),
        fixed_in,
        ..Default::default()
    }
}

/// Map GitHub's advisory severity string onto our enum. Mirrors
/// `parseSeverity`.
fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MODERATE" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Map the domain Ecosystem onto GitHub's `SecurityAdvisoryEcosystem`
/// enum values. `None` for ecosystems GHSA doesn't index. Mirrors
/// `ghsaEco` (GraphQL uses upper-case enum members).
fn ghsa_ecosystem(eco: Ecosystem) -> Option<&'static str> {
    Some(match eco {
        Ecosystem::Npm => "NPM",
        Ecosystem::PyPI => "PIP",
        Ecosystem::Crates => "RUST",
        Ecosystem::Go => "GO",
        Ecosystem::RubyGems => "RUBYGEMS",
        Ecosystem::Maven => "MAVEN",
        Ecosystem::Packagist => "COMPOSER",
        Ecosystem::NuGet => "NUGET",
        Ecosystem::Hex => "ERLANG",
        Ecosystem::Pub => "PUB",
        Ecosystem::SwiftPM => "SWIFT",
        Ecosystem::Cran
        | Ecosystem::Hackage
        | Ecosystem::Cpan
        | Ecosystem::CocoaPods
        | Ecosystem::Neovim
        | Ecosystem::Aur
        | Ecosystem::Conan
        | Ecosystem::Nix
        | Ecosystem::Julia
        | Ecosystem::Conda
        | Ecosystem::Nimble
        | Ecosystem::Elm
        | Ecosystem::Opam => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    const OK_BODY: &str = r#"{
        "data": {
            "securityVulnerabilities": {
                "nodes": [
                    {
                        "advisory": {
                            "ghsaId": "GHSA-jvqj-7wpc-9bqp",
                            "summary": "Prototype pollution in lodash",
                            "severity": "HIGH",
                            "permalink": "https://github.com/advisories/GHSA-jvqj-7wpc-9bqp",
                            "identifiers": [
                                {"type": "GHSA", "value": "GHSA-jvqj-7wpc-9bqp"},
                                {"type": "CVE", "value": "CVE-2018-16487"}
                            ]
                        },
                        "firstPatchedVersion": {"identifier": "4.17.11"},
                        "vulnerableVersionRange": "< 4.17.11"
                    }
                ]
            }
        }
    }"#;

    fn npm_query(name: &str, version: &str) -> AdvisoryQuery {
        AdvisoryQuery {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
        }
    }

    #[test]
    fn lookup_parses_graphql_response() {
        let base = "https://gh.test";
        let http = MockHttpClient::new().with(
            &format!("{base}/graphql"),
            200,
            OK_BODY.as_bytes().to_vec(),
        );
        let client = GhsaClient::new(base).with_token("ghp_token");

        let queries = vec![npm_query("lodash", "4.17.4")];
        let result = client.lookup(&http, &queries);

        let advs = &result["npm/lodash@4.17.4"];
        assert_eq!(advs.len(), 1);
        let a = &advs[0];
        assert_eq!(a.id, "GHSA-jvqj-7wpc-9bqp");
        assert_eq!(a.severity, Severity::High);
        assert_eq!(a.summary, "Prototype pollution in lodash");
        assert_eq!(a.url, "https://github.com/advisories/GHSA-jvqj-7wpc-9bqp");
        assert_eq!(a.source, "ghsa");
        assert_eq!(a.fixed_in, "4.17.11");
        assert_eq!(a.aliases, vec!["CVE-2018-16487"]);
        assert_eq!(a.epss, 0.0);
        assert!(!a.in_kev);
    }

    #[test]
    fn same_package_versions_share_one_call() {
        let base = "https://gh.test";
        let http = MockHttpClient::new().with(
            &format!("{base}/graphql"),
            200,
            OK_BODY.as_bytes().to_vec(),
        );
        let client = GhsaClient::new(base).with_token("t");

        let queries = vec![npm_query("lodash", "4.17.4"), npm_query("lodash", "4.17.5")];
        let result = client.lookup(&http, &queries);

        assert_eq!(result["npm/lodash@4.17.4"].len(), 1);
        assert_eq!(result["npm/lodash@4.17.5"].len(), 1);
        // Grouped by package → a single GraphQL POST.
        assert_eq!(http.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn missing_token_yields_empty_no_network() {
        let http = MockHttpClient::new();
        let client = GhsaClient::new("https://gh.test"); // no token
        let queries = vec![npm_query("lodash", "4.17.4")];
        let result = client.lookup(&http, &queries);

        assert!(result["npm/lodash@4.17.4"].is_empty());
        assert_eq!(http.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn empty_token_yields_empty_no_network() {
        let http = MockHttpClient::new();
        let client = GhsaClient::new("https://gh.test").with_token("");
        let queries = vec![npm_query("lodash", "4.17.4")];
        let result = client.lookup(&http, &queries);

        assert!(result["npm/lodash@4.17.4"].is_empty());
        assert_eq!(http.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn http_error_degrades_to_empty() {
        // Endpoint 404s (unregistered) → no advisories, no panic.
        let http = MockHttpClient::new();
        let client = GhsaClient::new("https://gh.test").with_token("t");
        let queries = vec![npm_query("lodash", "4.17.4")];
        let result = client.lookup(&http, &queries);
        assert!(result["npm/lodash@4.17.4"].is_empty());
    }

    #[test]
    fn exhausted_rate_limit_stops_the_batch_early() {
        let base = "https://gh.test";
        // X-RateLimit-Remaining: 0 on the (single) GraphQL URL → after the
        // first package the batch must stop rather than fire more doomed
        // requests. Packages are visited sorted, so "express" (< "lodash")
        // is fetched and "lodash" is skipped.
        let http = MockHttpClient::new().with_headers(
            &format!("{base}/graphql"),
            200,
            OK_BODY.as_bytes().to_vec(),
            &[("X-RateLimit-Remaining", "0")],
        );
        let client = GhsaClient::new(base).with_token("t");

        let queries = vec![npm_query("lodash", "4.17.4"), npm_query("express", "4.0.0")];
        let result = client.lookup(&http, &queries);

        // Exactly one call made (broke after the first sorted package).
        assert_eq!(http.calls.lock().unwrap().len(), 1);
        // express fetched (OK_BODY advisory), lodash left empty by the stop.
        assert_eq!(result["npm/express@4.0.0"].len(), 1);
        assert!(result["npm/lodash@4.17.4"].is_empty());
    }

    #[test]
    fn bad_json_degrades_to_empty() {
        let base = "https://gh.test";
        let http =
            MockHttpClient::new().with(&format!("{base}/graphql"), 200, b"not json".to_vec());
        let client = GhsaClient::new(base).with_token("t");
        let queries = vec![npm_query("lodash", "4.17.4")];
        let result = client.lookup(&http, &queries);
        assert!(result["npm/lodash@4.17.4"].is_empty());
    }

    #[test]
    fn unsupported_ecosystem_dropped() {
        // CocoaPods isn't a GHSA ecosystem → no network call, empty result.
        let http = MockHttpClient::new();
        let client = GhsaClient::new("https://gh.test").with_token("t");
        let queries = vec![AdvisoryQuery {
            ecosystem: Ecosystem::CocoaPods,
            name: "Alamofire".into(),
            version: "5.8.0".into(),
        }];
        let result = client.lookup(&http, &queries);
        assert!(result["cocoapods/Alamofire@5.8.0"].is_empty());
        assert_eq!(http.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn severity_maps_github_strings() {
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("MODERATE"), Severity::Medium);
        assert_eq!(parse_severity("LOW"), Severity::Low);
        assert_eq!(parse_severity("whatever"), Severity::Info);
    }

    #[test]
    fn parse_handles_missing_patch_and_cve() {
        let raw = br#"{"data":{"securityVulnerabilities":{"nodes":[
            {"advisory":{"ghsaId":"GHSA-aaaa-bbbb-cccc","summary":"x","severity":"MODERATE",
                "permalink":"https://example/GHSA","identifiers":[]},
             "firstPatchedVersion":null}
        ]}}}"#;
        let advs = parse_ghsa_response(raw).unwrap();
        assert_eq!(advs.len(), 1);
        assert_eq!(advs[0].severity, Severity::Medium);
        assert_eq!(advs[0].fixed_in, "");
        assert!(advs[0].aliases.is_empty());
    }
}
