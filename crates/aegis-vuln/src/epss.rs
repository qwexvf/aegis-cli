//! FIRST.org EPSS adapter. Port of `internal/infra/epss/client.go`.
//!
//! Fills `epss` + `epss_percentile` on advisories carrying a CVE ID
//! (primary or alias). No auth; batches up to 100 CVEs per request.
//! Network failures degrade gracefully — un-enriched advisories are
//! returned, never an error.

use std::collections::HashMap;

use aegis_domain::Advisory;
use aegis_net::HttpClient;
use serde::Deserialize;

pub const DEFAULT_BASE_URL: &str = "https://api.first.org";
const MAX_CVES_PER_BATCH: usize = 100;

pub struct EpssClient {
    base_url: String,
}

impl Default for EpssClient {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

#[derive(Deserialize, Default)]
struct EpssData {
    #[serde(default)]
    cve: String,
    #[serde(default)]
    epss: String,
    #[serde(default)]
    percentile: String,
}

#[derive(Deserialize, Default)]
struct EpssResp {
    #[serde(default)]
    data: Vec<EpssData>,
}

#[derive(Clone, Copy)]
struct Score {
    epss: f64,
    percentile: f64,
}

impl EpssClient {
    pub fn new(base_url: &str) -> Self {
        EpssClient {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Enrich advisories in place-by-return. Mirrors `EnrichAdvisories`.
    pub fn enrich_advisories(
        &self,
        http: &dyn HttpClient,
        mut advs: Vec<Advisory>,
    ) -> Vec<Advisory> {
        // CVE → first advisory index carrying it.
        let mut cve_index: HashMap<String, usize> = HashMap::new();
        let mut cve_ids: Vec<String> = Vec::new();
        for (i, a) in advs.iter().enumerate() {
            let Some(cve) = find_cve_id(a) else { continue };
            cve_index.entry(cve.clone()).or_insert_with(|| {
                cve_ids.push(cve);
                i
            });
        }
        if cve_ids.is_empty() {
            return advs;
        }

        let scores = self.fetch_batch(http, &cve_ids);
        for (cve, score) in scores {
            if let Some(&idx) = cve_index.get(&cve) {
                advs[idx].epss = score.epss;
                advs[idx].epss_percentile = score.percentile;
            }
        }
        advs
    }

    fn fetch_batch(&self, http: &dyn HttpClient, cve_ids: &[String]) -> HashMap<String, Score> {
        let mut result = HashMap::new();
        for batch in cve_ids.chunks(MAX_CVES_PER_BATCH) {
            if let Ok(partial) = self.fetch_one_batch(http, batch) {
                result.extend(partial);
            }
            // best-effort: a failed batch just leaves those CVEs unscored.
        }
        result
    }

    fn fetch_one_batch(
        &self,
        http: &dyn HttpClient,
        cve_ids: &[String],
    ) -> Result<HashMap<String, Score>, String> {
        let url = format!("{}/data/v1/epss?cve={}", self.base_url, cve_ids.join(","));
        let resp = http
            .get(&url, &[("Accept", "application/json")])
            .map_err(|e| format!("epss batch: {e}"))?;
        if !resp.is_ok() {
            return Err(format!("epss batch: HTTP {}", resp.status));
        }
        let parsed: EpssResp =
            serde_json::from_slice(&resp.body).map_err(|e| format!("epss batch decode: {e}"))?;
        let mut out = HashMap::new();
        for d in parsed.data {
            // Skip malformed entries rather than storing 0.0.
            let (Ok(epss), Ok(percentile)) = (d.epss.parse::<f64>(), d.percentile.parse::<f64>())
            else {
                continue;
            };
            out.insert(d.cve, Score { epss, percentile });
        }
        Ok(out)
    }
}

/// CVE ID from the advisory (primary ID first, then aliases). Mirrors
/// `findCVEID`.
fn find_cve_id(a: &Advisory) -> Option<String> {
    if a.id.starts_with("CVE-") {
        return Some(a.id.clone());
    }
    a.aliases
        .iter()
        .find(|alias| alias.starts_with("CVE-"))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    fn adv(id: &str, aliases: &[&str]) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn enriches_by_cve_primary_and_alias() {
        let base = "https://epss.test";
        let body = r#"{"status":"OK","data":[
            {"cve":"CVE-2021-1","epss":"0.94","percentile":"0.99"},
            {"cve":"CVE-2021-2","epss":"0.01","percentile":"0.20"}
        ]}"#;
        // both CVEs land in one batch → one URL with joined ids.
        let url = format!("{base}/data/v1/epss?cve=CVE-2021-1,CVE-2021-2");
        let http = MockHttpClient::new().with(&url, 200, body.as_bytes().to_vec());

        let advs = vec![
            adv("CVE-2021-1", &[]),            // primary is a CVE
            adv("GHSA-xxxx", &["CVE-2021-2"]), // CVE via alias
            adv("GHSA-yyyy", &[]),             // no CVE → untouched
        ];
        let out = EpssClient::new(base).enrich_advisories(&http, advs);
        assert!((out[0].epss - 0.94).abs() < 1e-9);
        assert!((out[1].epss_percentile - 0.20).abs() < 1e-9);
        assert_eq!(out[2].epss, 0.0);
    }

    #[test]
    fn no_cve_means_no_http_call() {
        let http = MockHttpClient::new();
        let advs = vec![adv("GHSA-only", &[])];
        let out = EpssClient::new("https://epss.test").enrich_advisories(&http, advs);
        assert_eq!(out[0].epss, 0.0);
        assert_eq!(http.calls.lock().unwrap().len(), 0);
    }
}
