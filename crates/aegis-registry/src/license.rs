//! Per-ecosystem license fetchers + a dispatcher. Ports of each
//! `*registry` client's `FetchLicense` plus `licensefetch.Fetcher`.
//!
//! Every fetch degrades to `None` on any failure (404, transport, HTTP
//! error, empty license) — license data is best-effort, so it never
//! blocks a scan. Ecosystems without a compiled-in fetcher return `None`.

use aegis_domain::Ecosystem;
use aegis_net::HttpClient;
use serde_json::Value;

/// Dispatches license lookups to the per-ecosystem fetcher. Base URLs
/// default to the public registries; override for tests. Mirrors
/// `licensefetch.Fetcher`.
pub struct LicenseFetcher {
    pub npm_base: String,
    pub pypi_base: String,
    pub crates_base: String,
    pub rubygems_base: String,
    pub nuget_base: String,
}

impl Default for LicenseFetcher {
    fn default() -> Self {
        LicenseFetcher {
            npm_base: "https://registry.npmjs.org".into(),
            pypi_base: "https://pypi.org".into(),
            crates_base: "https://crates.io".into(),
            rubygems_base: "https://rubygems.org".into(),
            nuget_base: "https://api.nuget.org".into(),
        }
    }
}

impl LicenseFetcher {
    /// Look up the SPDX license for a package version. `None` when the
    /// ecosystem has no compiled-in fetcher or the registry reports none.
    /// Mirrors `Fetcher.FetchLicense`.
    #[allow(unused_variables)]
    pub fn fetch_license(
        &self,
        http: &dyn HttpClient,
        eco: Ecosystem,
        name: &str,
        version: &str,
    ) -> Option<String> {
        if name.is_empty() || version.is_empty() {
            return None;
        }
        match eco {
            #[cfg(feature = "npm")]
            Ecosystem::Npm => npm_license(http, &self.npm_base, name, version),
            #[cfg(feature = "pypi")]
            Ecosystem::PyPI => pypi_license(http, &self.pypi_base, name, version),
            #[cfg(feature = "crates")]
            Ecosystem::Crates => crates_license(http, &self.crates_base, name, version),
            #[cfg(feature = "rubygems")]
            Ecosystem::RubyGems => rubygems_license(http, &self.rubygems_base, name, version),
            #[cfg(feature = "nuget")]
            Ecosystem::NuGet => nuget_license(http, &self.nuget_base, name, version),
            _ => None,
        }
    }
}

/// GET a URL and parse the body as JSON; None on any non-2xx / parse error.
// Used only by the per-ecosystem license fetchers below, all feature-gated —
// dead in a zero-feature build.
#[allow(dead_code)]
fn get_json(http: &dyn HttpClient, url: &str, headers: &[(&str, &str)]) -> Option<Value> {
    let resp = http.get(url, headers).ok()?;
    if !resp.is_ok() {
        return None;
    }
    serde_json::from_slice(&resp.body).ok()
}

#[allow(dead_code)]
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// --- npm -------------------------------------------------------------

#[cfg(feature = "npm")]
fn npm_license(http: &dyn HttpClient, base: &str, name: &str, version: &str) -> Option<String> {
    // Scoped names encode the slash: @scope/name → @scope%2Fname.
    let encoded = if name.starts_with('@') {
        name.replacen('/', "%2F", 1)
    } else {
        name.to_string()
    };
    let url = format!("{base}/{encoded}/{version}");
    let doc = get_json(http, &url, &[])?;
    parse_npm_license(&doc)
}

/// SPDX id from an npm version doc, tolerating the three historical
/// shapes: string, object {"type":..}, legacy array [{"type":..}].
/// Mirrors `parseNpmLicense` + `npmLicenseField`.
#[cfg(feature = "npm")]
fn parse_npm_license(doc: &Value) -> Option<String> {
    npm_license_field(doc.get("license")).or_else(|| npm_license_field(doc.get("licenses")))
}

#[cfg(feature = "npm")]
fn npm_license_field(v: Option<&Value>) -> Option<String> {
    let v = v?;
    if let Some(s) = v.as_str() {
        return non_empty(s);
    }
    if let Some(t) = v.get("type").and_then(|t| t.as_str()) {
        return non_empty(t);
    }
    if let Some(arr) = v.as_array() {
        let types: Vec<&str> = arr
            .iter()
            .filter_map(|e| e.get("type").and_then(|t| t.as_str()))
            .filter(|t| !t.is_empty())
            .collect();
        if !types.is_empty() {
            return Some(types.join(" OR "));
        }
    }
    None
}

// --- pypi ------------------------------------------------------------

#[cfg(feature = "pypi")]
fn pypi_license(http: &dyn HttpClient, base: &str, name: &str, version: &str) -> Option<String> {
    let url = format!("{base}/pypi/{name}/{version}/json");
    let doc = get_json(http, &url, &[])?;
    let lic = doc.get("info")?.get("license")?.as_str()?;
    non_empty(lic)
}

// --- crates ----------------------------------------------------------

#[cfg(feature = "crates")]
fn crates_license(http: &dyn HttpClient, base: &str, name: &str, version: &str) -> Option<String> {
    let url = format!("{base}/api/v1/crates/{name}/{version}");
    // crates.io requires an identifying User-Agent.
    let doc = get_json(
        http,
        &url,
        &[(
            "User-Agent",
            "aegis-cli (https://github.com/qwexvf/aegis-cli)",
        )],
    )?;
    let lic = doc.get("version")?.get("license")?.as_str()?;
    non_empty(lic)
}

// --- rubygems --------------------------------------------------------

#[cfg(feature = "rubygems")]
fn rubygems_license(
    http: &dyn HttpClient,
    base: &str,
    name: &str,
    version: &str,
) -> Option<String> {
    let url = format!("{base}/api/v2/rubygems/{name}/versions/{version}.json");
    let doc = get_json(http, &url, &[])?;
    let arr = doc.get("licenses")?.as_array()?;
    let licenses: Vec<&str> = arr
        .iter()
        .filter_map(|l| l.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    if licenses.is_empty() {
        None
    } else {
        Some(licenses.join(" OR "))
    }
}

// --- nuget -----------------------------------------------------------

#[cfg(feature = "nuget")]
fn nuget_license(http: &dyn HttpClient, base: &str, name: &str, version: &str) -> Option<String> {
    // Registration API uses lowercase name + version.
    let url = format!(
        "{base}/v3/registration5-gz-semver2/{}/{}.json",
        name.to_lowercase(),
        version.to_lowercase()
    );
    let doc = get_json(http, &url, &[])?;
    let entry = doc.get("catalogEntry")?;
    // Prefer SPDX licenseExpression over the legacy licenseUrl.
    if let Some(expr) = entry.get("licenseExpression").and_then(|v| v.as_str()) {
        if let Some(s) = non_empty(expr) {
            return Some(s);
        }
    }
    entry
        .get("licenseUrl")
        .and_then(|v| v.as_str())
        .and_then(non_empty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    #[test]
    fn npm_license_string_object_array_shapes() {
        let base = "https://reg.test";
        let http = MockHttpClient::new()
            .with(
                &format!("{base}/lodash/4.17.21"),
                200,
                br#"{"license":"MIT"}"#.to_vec(),
            )
            .with(
                &format!("{base}/old/1.0.0"),
                200,
                br#"{"license":{"type":"ISC"}}"#.to_vec(),
            )
            .with(
                &format!("{base}/legacy/1.0.0"),
                200,
                br#"{"licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}"#.to_vec(),
            );
        let lf = LicenseFetcher {
            npm_base: base.into(),
            ..Default::default()
        };
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::Npm, "lodash", "4.17.21")
                .as_deref(),
            Some("MIT")
        );
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::Npm, "old", "1.0.0")
                .as_deref(),
            Some("ISC")
        );
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::Npm, "legacy", "1.0.0")
                .as_deref(),
            Some("MIT OR Apache-2.0")
        );
    }

    #[test]
    fn scoped_npm_name_encodes_slash() {
        let base = "https://reg.test";
        let http = MockHttpClient::new().with(
            &format!("{base}/@scope%2Fpkg/1.0.0"),
            200,
            br#"{"license":"MIT"}"#.to_vec(),
        );
        let lf = LicenseFetcher {
            npm_base: base.into(),
            ..Default::default()
        };
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::Npm, "@scope/pkg", "1.0.0")
                .as_deref(),
            Some("MIT")
        );
    }

    #[test]
    fn pypi_crates_rubygems_nuget() {
        let http = MockHttpClient::new()
            .with(
                "https://p.test/pypi/flask/3.0.0/json",
                200,
                br#"{"info":{"license":"BSD-3-Clause"}}"#.to_vec(),
            )
            .with(
                "https://c.test/api/v1/crates/serde/1.0.0",
                200,
                br#"{"version":{"license":"MIT OR Apache-2.0"}}"#.to_vec(),
            )
            .with(
                "https://r.test/api/v2/rubygems/rails/versions/7.1.0.json",
                200,
                br#"{"licenses":["MIT"]}"#.to_vec(),
            )
            .with(
                "https://n.test/v3/registration5-gz-semver2/newtonsoft.json/13.0.3.json",
                200,
                br#"{"catalogEntry":{"licenseExpression":"MIT"}}"#.to_vec(),
            );
        let lf = LicenseFetcher {
            pypi_base: "https://p.test".into(),
            crates_base: "https://c.test".into(),
            rubygems_base: "https://r.test".into(),
            nuget_base: "https://n.test".into(),
            ..Default::default()
        };
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::PyPI, "flask", "3.0.0")
                .as_deref(),
            Some("BSD-3-Clause")
        );
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::Crates, "serde", "1.0.0")
                .as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::RubyGems, "rails", "7.1.0")
                .as_deref(),
            Some("MIT")
        );
        assert_eq!(
            lf.fetch_license(&http, Ecosystem::NuGet, "Newtonsoft.Json", "13.0.3")
                .as_deref(),
            Some("MIT")
        );
    }

    #[test]
    fn missing_or_unsupported_returns_none() {
        let http = MockHttpClient::new(); // everything 404s
        let lf = LicenseFetcher::default();
        assert!(lf
            .fetch_license(&http, Ecosystem::Npm, "ghost", "9.9.9")
            .is_none());
        // Go/Gleam have no license fetcher → None, no HTTP call.
        assert!(lf.fetch_license(&http, Ecosystem::Go, "x", "1").is_none());
        assert!(lf
            .fetch_license(&http, Ecosystem::Npm, "", "1.0.0")
            .is_none());
    }
}
