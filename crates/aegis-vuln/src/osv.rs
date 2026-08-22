//! OSV.dev adapter. Port of `internal/infra/osv/client.go`.
//!
//! Two-phase fetch: POST `/v1/querybatch` for advisory IDs per query,
//! then GET `/v1/vulns/{id}` for each unique ID. Ecosystems OSV can't
//! cover are dropped from the batch (one bad entry 400s the whole call).
//!
//! An optional [`DiskCache`] (Go's `WithCacheDir`) backs the per-advisory GET
//! `/v1/vulns/{id}`. Advisory documents are effectively immutable, so caching
//! them by id avoids re-fetching the same GHSA/CVE across deps and runs. The
//! version-specific batch query is never cached (new advisories land daily).

use std::collections::HashMap;

use aegis_domain::{Advisory, AdvisoryQuery, Ecosystem, Severity};
use aegis_net::{DiskCache, HttpClient};
use serde::Deserialize;

/// Public OSV.dev API. Override for self-hosted deployments / tests.
pub const DEFAULT_BASE_URL: &str = "https://api.osv.dev";

/// OSV.dev's documented per-request cap; larger snapshots are chunked.
pub const MAX_QUERIES_PER_BATCH: usize = 1000;

pub struct OsvClient {
    base_url: String,
    cache: Option<DiskCache>,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

impl OsvClient {
    pub fn new(base_url: &str) -> Self {
        OsvClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            cache: None,
        }
    }

    /// Back the immutable per-advisory GETs with an on-disk cache (set its TTL
    /// on the `DiskCache`). Batch queries stay uncached.
    pub fn with_cache(mut self, cache: DiskCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Two-phase lookup. Returns a map keyed by [`AdvisoryQuery::key`];
    /// every input query gets an entry (empty vec = "looked up, none
    /// found"). Mirrors `Client.Lookup`.
    pub fn lookup(
        &self,
        http: &dyn HttpClient,
        queries: &[AdvisoryQuery],
    ) -> Result<HashMap<String, Vec<Advisory>>, String> {
        let mut out: HashMap<String, Vec<Advisory>> = HashMap::new();
        for q in queries {
            out.insert(q.key(), Vec::new());
        }

        for chunk in queries.chunks(MAX_QUERIES_PER_BATCH) {
            let ids = self.batch_ids(http, chunk)?;
            for (i, query_ids) in ids.into_iter().enumerate() {
                let advs = self.fetch_advisories(http, &query_ids)?;
                out.insert(chunk[i].key(), advs);
            }
        }
        Ok(out)
    }

    /// One `/v1/querybatch` call → a parallel vec of advisory IDs per
    /// input query (empty when no matches). Mirrors `batchIDs`.
    fn batch_ids(
        &self,
        http: &dyn HttpClient,
        queries: &[AdvisoryQuery],
    ) -> Result<Vec<Vec<String>>, String> {
        // Build the batch from OSV-supported ecosystems only; remember
        // each sent query's original index to realign the results.
        let mut batch_queries = Vec::new();
        let mut supported_idx = Vec::new();
        for (i, q) in queries.iter().enumerate() {
            let Some(eco) = osv_ecosystem(q.ecosystem) else {
                continue;
            };
            batch_queries.push(serde_json::json!({
                "package": { "name": osv_package_name(q), "ecosystem": eco },
                "version": q.version,
            }));
            supported_idx.push(i);
        }

        let mut ids: Vec<Vec<String>> = vec![Vec::new(); queries.len()];
        if batch_queries.is_empty() {
            return Ok(ids);
        }

        let body = serde_json::to_vec(&serde_json::json!({ "queries": batch_queries }))
            .map_err(|e| format!("osv batch marshal: {e}"))?;
        let resp = http
            .post(
                &format!("{}/v1/querybatch", self.base_url),
                &body,
                &[
                    ("Content-Type", "application/json"),
                    ("Accept", "application/json"),
                ],
            )
            .map_err(|e| format!("osv batch: {e}"))?;
        if !resp.is_ok() {
            return Err(format!("osv batch: HTTP {}", resp.status));
        }

        let parsed: BatchResp =
            serde_json::from_slice(&resp.body).map_err(|e| format!("osv batch decode: {e}"))?;
        if parsed.results.len() != batch_queries.len() {
            return Err(format!(
                "osv batch: result count {} != query count {}",
                parsed.results.len(),
                batch_queries.len()
            ));
        }

        for (j, r) in parsed.results.iter().enumerate() {
            let orig = supported_idx[j];
            for v in &r.vulns {
                // Defense in depth: the ID flows into URL paths.
                if is_valid_osv_id(&v.id) {
                    ids[orig].push(v.id.clone());
                }
            }
        }
        Ok(ids)
    }

    /// Resolve advisory IDs into full [`Advisory`] records; dedupes IDs.
    /// A single failed fetch degrades to a stub (id + pivot URL) rather
    /// than failing the whole snapshot. Mirrors `fetchAdvisories`.
    fn fetch_advisories(
        &self,
        http: &dyn HttpClient,
        ids: &[String],
    ) -> Result<Vec<Advisory>, String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for id in ids {
            if !seen.insert(id.clone()) {
                continue;
            }
            match self.fetch_one_advisory(http, id) {
                Ok(adv) => out.push(adv),
                Err(e) => out.push(Advisory {
                    id: id.clone(),
                    severity: Severity::Info,
                    summary: format!("(failed to fetch full advisory: {e})"),
                    url: format!("https://osv.dev/vulnerability/{id}"),
                    source: "osv".to_string(),
                    ..Default::default()
                }),
            }
        }
        Ok(out)
    }

    fn fetch_one_advisory(&self, http: &dyn HttpClient, id: &str) -> Result<Advisory, String> {
        if !is_valid_osv_id(id) {
            return Err(format!("invalid id {id:?}"));
        }
        // is_valid_osv_id already restricts id to a filesystem-safe charset,
        // so it's safe to use directly in the cache key.
        let cache_key = format!("osv-vuln-{id}.json");
        if let Some(cache) = &self.cache {
            if let Some(body) = cache.get(&cache_key) {
                if let Ok(adv) = parse_osv_vuln(&body) {
                    return Ok(adv);
                }
            }
        }
        let resp = http
            .get(
                &format!("{}/v1/vulns/{}", self.base_url, id),
                &[("Accept", "application/json")],
            )
            .map_err(|e| format!("osv vuln {id}: {e}"))?;
        if !resp.is_ok() {
            return Err(format!("HTTP {}", resp.status));
        }
        let adv = parse_osv_vuln(&resp.body)?;
        if let Some(cache) = &self.cache {
            let _ = cache.put(&cache_key, &resp.body);
        }
        Ok(adv)
    }
}

// --- wire types ------------------------------------------------------

#[derive(Deserialize)]
struct BatchVuln {
    #[serde(default)]
    id: String,
}
#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVuln>,
}
#[derive(Deserialize)]
struct BatchResp {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct OsvSeverityIn {
    #[serde(default)]
    score: String,
}

#[derive(Deserialize, Default)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: String,
}

#[derive(Deserialize, Default)]
struct RangeEvent {
    #[serde(default)]
    fixed: String,
}
#[derive(Deserialize, Default)]
struct OsvRange {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<RangeEvent>,
}
#[derive(Deserialize, Default)]
struct EcosystemSpecific {
    #[serde(default)]
    functions: Vec<String>,
}
#[derive(Deserialize, Default)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    ecosystem_specific: EcosystemSpecific,
}

#[derive(Deserialize, Default)]
struct OsvDoc {
    #[serde(default)]
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    severity: Vec<OsvSeverityIn>,
    #[serde(default)]
    database_specific: DatabaseSpecific,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

// --- pure mapping (unit-testable) ------------------------------------

/// Decode an OSV vulnerability JSON document into an [`Advisory`].
/// Mirrors `parseOSVVuln`.
pub fn parse_osv_vuln(raw: &[u8]) -> Result<Advisory, String> {
    let doc: OsvDoc = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if !is_valid_osv_id(&doc.id) {
        return Err(format!("invalid id {:?} in response", doc.id));
    }
    let summary = if !doc.summary.is_empty() {
        doc.summary.clone()
    } else {
        let fl = first_line(&doc.details);
        if fl.is_empty() {
            "(no summary provided)".to_string()
        } else {
            fl.to_string()
        }
    };
    Ok(Advisory {
        severity: severity_from_osv(&doc.severity, &doc.database_specific.severity),
        url: format!("https://osv.dev/vulnerability/{}", doc.id),
        source: "osv".to_string(),
        fixed_in: fix_version_from_affected(&doc.affected),
        affected_functions: affected_functions(&doc.affected),
        aliases: doc.aliases,
        summary,
        id: doc.id,
        ..Default::default()
    })
}

/// Union of function names across all affected[] entries. Mirrors
/// `affectedFunctions`.
fn affected_functions(affected: &[OsvAffected]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for a in affected {
        for fn_name in &a.ecosystem_specific.functions {
            if !fn_name.is_empty() && seen.insert(fn_name.clone()) {
                out.push(fn_name.clone());
            }
        }
    }
    out
}

/// First "fixed" version from SEMVER/ECOSYSTEM ranges (GIT SHAs skipped).
/// Mirrors `fixVersionFromAffected`.
fn fix_version_from_affected(affected: &[OsvAffected]) -> String {
    for a in affected {
        for r in &a.ranges {
            if r.kind != "SEMVER" && r.kind != "ECOSYSTEM" {
                continue;
            }
            for e in &r.events {
                if !e.fixed.is_empty() {
                    return e.fixed.clone();
                }
            }
        }
    }
    String::new()
}

/// Map OSV's severity surface onto our enum: CVSS vector first, then
/// database_specific.severity. Mirrors `severityFromOSV`.
fn severity_from_osv(sevs: &[OsvSeverityIn], db_specific: &str) -> Severity {
    for s in sevs {
        if let Some(score) = cvss_base_score(&s.score) {
            return bucket_cvss(score);
        }
    }
    match db_specific.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MODERATE" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// CVSS v3.x base score from a vector string, or None when absent /
/// unparseable. Mirrors `cvssBaseScore` (returns -1 there).
fn cvss_base_score(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:") {
        return None;
    }
    let parts: Vec<&str> = vector.split('/').collect();
    if parts.len() < 9 {
        return None;
    }
    let mut m: HashMap<&str, &str> = HashMap::new();
    for p in &parts[1..] {
        let (k, v) = p.split_once(':')?;
        m.insert(k, v);
    }
    let get = |key: &str, table: &[(&str, f64)]| -> Option<f64> {
        let val = m.get(key)?;
        table.iter().find(|(k, _)| k == val).map(|(_, v)| *v)
    };

    let av = get("AV", &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.20)])?;
    let ac = get("AC", &[("L", 0.77), ("H", 0.44)])?;
    let ui = get("UI", &[("N", 0.85), ("R", 0.62)])?;

    let scope = *m.get("S")?;
    let scope_changed = scope == "C";
    if !scope_changed && scope != "U" {
        return None;
    }

    let pr_vals: &[(&str, f64)] = if scope_changed {
        &[("N", 0.85), ("L", 0.68), ("H", 0.50)]
    } else {
        &[("N", 0.85), ("L", 0.62), ("H", 0.27)]
    };
    let pr = get("PR", pr_vals)?;

    let impact_vals = &[("N", 0.00), ("L", 0.22), ("H", 0.56)];
    let conf = get("C", impact_vals)?;
    let integ = get("I", impact_vals)?;
    let avail = get("A", impact_vals)?;

    let iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail);

    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // CVSS roundup: smallest 1-decimal value >= input.
    Some((raw * 10.0).ceil() / 10.0)
}

/// Map a CVSS v3 base score onto Severity per FIRST.org thresholds.
/// Mirrors `bucketCVSS`.
fn bucket_cvss(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn first_line(s: &str) -> &str {
    s.split_once('\n').map(|(a, _)| a).unwrap_or(s)
}

/// Documented OSV ID alphabet. Mirrors `isValidOSVID`.
fn is_valid_osv_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'))
}

/// Map the domain Ecosystem onto OSV's exact string vocabulary. None for
/// ecosystems OSV doesn't cover (CocoaPods, CPAN, Neovim, AUR). Mirrors
/// `osvEcosystem`.
fn osv_ecosystem(eco: Ecosystem) -> Option<&'static str> {
    Some(match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "PyPI",
        Ecosystem::Crates => "crates.io",
        Ecosystem::Go => "Go",
        Ecosystem::RubyGems => "RubyGems",
        Ecosystem::Maven => "Maven",
        Ecosystem::Packagist => "Packagist",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::Hex => "Hex",
        Ecosystem::Pub => "Pub",
        Ecosystem::SwiftPM => "SwiftURL",
        Ecosystem::Cran => "CRAN",
        Ecosystem::Hackage => "Hackage",
        Ecosystem::CocoaPods
        | Ecosystem::Cpan
        | Ecosystem::Neovim
        | Ecosystem::Aur
        | Ecosystem::Conan
        | Ecosystem::Nix
        | Ecosystem::Julia
        | Ecosystem::Conda
        | Ecosystem::Nimble => return None,
    })
}

/// OSV package name. SwiftURL keys on the repo URL with scheme + `.git`
/// stripped; others use the name verbatim. Mirrors `osvPackageName`.
fn osv_package_name(q: &AdvisoryQuery) -> String {
    if q.ecosystem != Ecosystem::SwiftPM {
        return q.name.clone();
    }
    let n = q.name.strip_suffix(".git").unwrap_or(&q.name);
    let n = n.strip_prefix("https://").unwrap_or(n);
    n.strip_prefix("http://").unwrap_or(n).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    #[test]
    fn cvss_critical_vector_scores_and_buckets() {
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 (critical).
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let score = cvss_base_score(v).unwrap();
        assert!((score - 9.8).abs() < 1e-9, "got {score}");
        assert_eq!(bucket_cvss(score), Severity::Critical);
    }

    #[test]
    fn cvss_rejects_non_cvss_and_short() {
        assert!(cvss_base_score("").is_none());
        assert!(cvss_base_score("MODERATE").is_none());
        assert!(cvss_base_score("CVSS:3.1/AV:N").is_none());
    }

    #[test]
    fn severity_falls_back_to_db_specific() {
        assert_eq!(severity_from_osv(&[], "MODERATE"), Severity::Medium);
        assert_eq!(severity_from_osv(&[], "critical"), Severity::Critical);
        assert_eq!(severity_from_osv(&[], "nonsense"), Severity::Info);
    }

    #[test]
    fn parse_vuln_maps_fields() {
        let raw = br#"{
            "id": "GHSA-jvqj-7wpc-9bqp",
            "aliases": ["CVE-2018-16487"],
            "summary": "Prototype pollution in lodash",
            "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{
                "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.11"}]}],
                "ecosystem_specific": {"functions":["template","_.template"]}
            }]
        }"#;
        let adv = parse_osv_vuln(raw).unwrap();
        assert_eq!(adv.id, "GHSA-jvqj-7wpc-9bqp");
        assert_eq!(adv.severity, Severity::Critical);
        assert_eq!(adv.fixed_in, "4.17.11");
        assert_eq!(adv.affected_functions, vec!["template", "_.template"]);
        assert_eq!(adv.url, "https://osv.dev/vulnerability/GHSA-jvqj-7wpc-9bqp");
        assert_eq!(adv.aliases, vec!["CVE-2018-16487"]);
    }

    #[test]
    fn osv_id_validation() {
        assert!(is_valid_osv_id("GHSA-jvqj-7wpc-9bqp"));
        assert!(is_valid_osv_id("CVE-2018-16487"));
        assert!(!is_valid_osv_id(""));
        assert!(!is_valid_osv_id("../etc/passwd"));
    }

    #[test]
    fn swift_package_name_strips_url() {
        let q = AdvisoryQuery {
            ecosystem: Ecosystem::SwiftPM,
            name: "https://github.com/vapor/vapor.git".into(),
            version: "4.0.0".into(),
        };
        assert_eq!(osv_package_name(&q), "github.com/vapor/vapor");
    }

    #[test]
    fn lookup_two_phase_with_mock() {
        let base = "https://osv.test";
        let batch_body = r#"{"results":[{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc"}]},{"vulns":[]}]}"#;
        let vuln_body = r#"{"id":"GHSA-aaaa-bbbb-cccc","summary":"bad","database_specific":{"severity":"HIGH"}}"#;
        let http = MockHttpClient::new()
            .with(
                &format!("{base}/v1/querybatch"),
                200,
                batch_body.as_bytes().to_vec(),
            )
            .with(
                &format!("{base}/v1/vulns/GHSA-aaaa-bbbb-cccc"),
                200,
                vuln_body.as_bytes().to_vec(),
            );

        let queries = vec![
            AdvisoryQuery {
                ecosystem: Ecosystem::Npm,
                name: "lodash".into(),
                version: "4.17.4".into(),
            },
            AdvisoryQuery {
                ecosystem: Ecosystem::Npm,
                name: "safe".into(),
                version: "1.0.0".into(),
            },
        ];
        let client = OsvClient::new(base);
        let result = client.lookup(&http, &queries).unwrap();

        let lodash = &result["npm/lodash@4.17.4"];
        assert_eq!(lodash.len(), 1);
        assert_eq!(lodash[0].severity, Severity::High);
        assert!(result["npm/safe@1.0.0"].is_empty());
    }

    #[test]
    fn cached_advisory_skips_per_vuln_fetch() {
        // Batch returns the id, but the /v1/vulns GET is NOT mocked (404). A
        // pre-seeded cache entry must satisfy the lookup, proving the immutable
        // advisory doc was served from disk.
        let base = "https://osv.test";
        let dir = std::env::temp_dir().join(format!("aegis-osv-cache-{}", std::process::id()));
        let cache = DiskCache::new(&dir, Some(std::time::Duration::from_secs(3600)));
        cache
            .put(
                "osv-vuln-GHSA-aaaa-bbbb-cccc.json",
                br#"{"id":"GHSA-aaaa-bbbb-cccc","summary":"cached","database_specific":{"severity":"HIGH"}}"#,
            )
            .unwrap();

        let batch_body = r#"{"results":[{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc"}]}]}"#;
        // Only the batch endpoint is mocked; the per-vuln GET 404s.
        let http = MockHttpClient::new().with(
            &format!("{base}/v1/querybatch"),
            200,
            batch_body.as_bytes().to_vec(),
        );
        let queries = vec![AdvisoryQuery {
            ecosystem: Ecosystem::Npm,
            name: "lodash".into(),
            version: "4.17.4".into(),
        }];
        let client = OsvClient::new(base).with_cache(cache);
        let result = client.lookup(&http, &queries).unwrap();
        let advs = &result["npm/lodash@4.17.4"];
        assert_eq!(advs.len(), 1, "cached advisory should have been returned");
        assert_eq!(advs[0].summary, "cached");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_ecosystem_dropped_from_batch() {
        // CocoaPods isn't in OSV → batch is empty → no HTTP call, empty result.
        let http = MockHttpClient::new();
        let queries = vec![AdvisoryQuery {
            ecosystem: Ecosystem::CocoaPods,
            name: "Alamofire".into(),
            version: "5.8.0".into(),
        }];
        let result = OsvClient::new("https://osv.test")
            .lookup(&http, &queries)
            .unwrap();
        assert!(result["cocoapods/Alamofire@5.8.0"].is_empty());
        assert_eq!(http.calls.lock().unwrap().len(), 0);
    }
}
