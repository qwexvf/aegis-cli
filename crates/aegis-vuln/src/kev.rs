//! CISA KEV adapter. Port of `internal/infra/kev/client.go`.
//!
//! Downloads the Known Exploited Vulnerabilities catalog and exposes it
//! as a CVE-ID set. Network/parse errors degrade to "not in KEV" so a
//! scan is never blocked. The 24h on-disk cache + lazy-load mutex from
//! the Go version are deferred to the cache layer; this port fetches the
//! feed once via `load` and answers membership from the returned set.

use std::collections::HashSet;

use aegis_domain::Advisory;
use aegis_net::HttpClient;
use serde::Deserialize;

pub const FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub struct KevCatalog {
    feed_url: String,
}

impl Default for KevCatalog {
    fn default() -> Self {
        Self::new(FEED_URL)
    }
}

#[derive(Deserialize, Default)]
struct KevVuln {
    #[serde(rename = "cveID", default)]
    cve_id: String,
}
#[derive(Deserialize, Default)]
struct KevFeed {
    #[serde(default)]
    vulnerabilities: Vec<KevVuln>,
}

impl KevCatalog {
    pub fn new(feed_url: &str) -> Self {
        KevCatalog {
            feed_url: feed_url.to_string(),
        }
    }

    /// Download + parse the KEV feed into a CVE-ID set. Errors degrade to
    /// an empty set (caller treats every CVE as not-in-KEV).
    pub fn load(&self, http: &dyn HttpClient) -> HashSet<String> {
        match self.download(http) {
            Ok(raw) => parse_kev(&raw),
            Err(_) => HashSet::new(),
        }
    }

    /// Set `in_kev` on every advisory whose CVE (primary or alias) is in
    /// the catalog. Loads the feed once.
    pub fn enrich_advisories(
        &self,
        http: &dyn HttpClient,
        mut advs: Vec<Advisory>,
    ) -> Vec<Advisory> {
        let set = self.load(http);
        if set.is_empty() {
            return advs;
        }
        for a in &mut advs {
            if cve_ids_of(a).any(|cve| set.contains(cve)) {
                a.in_kev = true;
            }
        }
        advs
    }

    fn download(&self, http: &dyn HttpClient) -> Result<Vec<u8>, String> {
        let resp = http
            .get(&self.feed_url, &[("Accept", "application/json")])
            .map_err(|e| format!("kev feed: {e}"))?;
        if !resp.is_ok() {
            return Err(format!("kev feed: HTTP {}", resp.status));
        }
        Ok(resp.body)
    }
}

/// Every CVE-shaped id on an advisory (primary + aliases).
fn cve_ids_of(a: &Advisory) -> impl Iterator<Item = &str> {
    std::iter::once(a.id.as_str())
        .chain(a.aliases.iter().map(|s| s.as_str()))
        .filter(|s| s.starts_with("CVE-"))
}

/// Parse the KEV feed JSON into a CVE-ID set. Mirrors `parseKEV`.
pub fn parse_kev(raw: &[u8]) -> HashSet<String> {
    let feed: KevFeed = serde_json::from_slice(raw).unwrap_or_default();
    feed.vulnerabilities
        .into_iter()
        .map(|v| v.cve_id)
        .filter(|id| !id.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    #[test]
    fn enriches_advisories_in_catalog() {
        let body = r#"{"vulnerabilities":[
            {"cveID":"CVE-2021-44228"},
            {"cveID":"CVE-2017-5638"}
        ]}"#;
        let http = MockHttpClient::new().with(FEED_URL, 200, body.as_bytes().to_vec());

        let advs = vec![
            Advisory {
                id: "CVE-2021-44228".into(),
                ..Default::default()
            },
            Advisory {
                id: "GHSA-x".into(),
                aliases: vec!["CVE-2017-5638".into()],
                ..Default::default()
            },
            Advisory {
                id: "CVE-2020-0001".into(),
                ..Default::default()
            },
        ];
        let out = KevCatalog::default().enrich_advisories(&http, advs);
        assert!(out[0].in_kev);
        assert!(out[1].in_kev); // via alias
        assert!(!out[2].in_kev);
    }

    #[test]
    fn feed_failure_degrades_to_not_in_kev() {
        let http = MockHttpClient::new(); // 404 for the feed
        let advs = vec![Advisory {
            id: "CVE-2021-44228".into(),
            ..Default::default()
        }];
        let out = KevCatalog::default().enrich_advisories(&http, advs);
        assert!(!out[0].in_kev);
    }
}
