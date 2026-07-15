//! npm packument adapter — the maintainer-hijack signal. Port of
//! `npmregistry.Client.FetchMaintainerSignal`.
//!
//! One full-packument GET yields publish times and per-version publisher
//! identity; a second best-effort GET adds last-week downloads. Everything
//! degrades to empty/zero on failure — the maintainer heuristics read absence
//! as "no signal", never as evidence.

use aegis_net::HttpClient;
use serde_json::Value;

/// The npm registry base (packument host).
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.npmjs.org";
/// The npm downloads-stats host — separate from the registry.
pub const DEFAULT_DOWNLOADS_URL: &str = "https://api.npmjs.org";

/// Registry-side metadata for one package version. Field-for-field mirror of
/// the heuristics `MaintainerSignal`; the caller copies it across (keeps the
/// registry and heuristics crates decoupled, as in the Go tree).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintainerSignal {
    pub published_at: String,
    pub weekly_downloads: i64,
    pub previous_version: String,
    pub previous_published_at: String,
    pub publisher: String,
    pub previous_publisher: String,
    pub version_unpublished: bool,
}

/// Fetches the maintainer-hijack signal for `name@version`. `registry_base`
/// and `downloads_base` are injectable for tests. Returns an empty signal on
/// any failure (empty inputs, transport error, non-2xx, unparseable body).
pub fn fetch_maintainer_signal(
    http: &dyn HttpClient,
    registry_base: &str,
    downloads_base: &str,
    name: &str,
    version: &str,
) -> MaintainerSignal {
    if name.is_empty() || version.is_empty() {
        return MaintainerSignal::default();
    }
    let encoded = encode_pkg(name);
    let url = format!("{registry_base}/{encoded}");
    let Some(doc) = get_json(http, &url) else {
        return MaintainerSignal::default();
    };

    // time[version] → published_at; versions[version]._npmUser.name → publisher.
    let time_map = doc.get("time").and_then(Value::as_object);
    let versions = doc.get("versions").and_then(Value::as_object);

    let published_at = time_map
        .and_then(|t| t.get(version))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let version_in_map = versions.is_some_and(|v| v.contains_key(version));
    let publisher = npm_user(versions, version);

    let (previous_version, previous_published_at) =
        previous_version(time_map, version, &published_at);
    let previous_publisher = if previous_version.is_empty() {
        String::new()
    } else {
        npm_user(versions, &previous_version)
    };

    let weekly_downloads = fetch_weekly_downloads(http, downloads_base, name);

    MaintainerSignal {
        // Time map retains a yanked version's entry, but the versions map
        // drops it — published-then-removed ⇒ unpublished.
        version_unpublished: !published_at.is_empty() && !version_in_map,
        published_at,
        weekly_downloads,
        previous_version,
        previous_published_at,
        publisher,
        previous_publisher,
    }
}

/// Encode a package name for a URL path: scoped `@scope/name` → `@scope%2Fname`.
fn encode_pkg(name: &str) -> String {
    if name.starts_with('@') {
        name.replacen('/', "%2F", 1)
    } else {
        name.to_string()
    }
}

fn get_json(http: &dyn HttpClient, url: &str) -> Option<Value> {
    let resp = http.get(url, &[]).ok()?;
    if !resp.is_ok() {
        return None;
    }
    serde_json::from_slice(&resp.body).ok()
}

/// Pull `versions[version]._npmUser.name` out of the packument.
fn npm_user(versions: Option<&serde_json::Map<String, Value>>, version: &str) -> String {
    versions
        .and_then(|v| v.get(version))
        .and_then(|entry| entry.get("_npmUser"))
        .and_then(|u| u.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Find the version published most recently BEFORE `current`, by the
/// packument's time map. RFC3339 timestamps sort lexically, so string
/// comparison is correct. Skips the `created`/`modified` meta keys.
fn previous_version(
    time_map: Option<&serde_json::Map<String, Value>>,
    current: &str,
    current_time: &str,
) -> (String, String) {
    if current_time.is_empty() {
        return (String::new(), String::new());
    }
    let Some(time_map) = time_map else {
        return (String::new(), String::new());
    };
    let mut best_ver = String::new();
    let mut best_time = String::new();
    for (ver, t) in time_map {
        if ver == current || ver == "created" || ver == "modified" {
            continue;
        }
        let Some(t) = t.as_str() else { continue };
        if t >= current_time {
            continue; // not earlier
        }
        if t > best_time.as_str() {
            best_ver = ver.clone();
            best_time = t.to_string();
        }
    }
    (best_ver, best_time)
}

/// Best-effort last-week downloads. Any failure (404 for scoped/unpublished,
/// transport, parse) yields 0 — read as "unknown", not "no users".
fn fetch_weekly_downloads(http: &dyn HttpClient, downloads_base: &str, name: &str) -> i64 {
    let encoded = encode_pkg(name);
    let url = format!("{downloads_base}/downloads/point/last-week/{encoded}");
    let Some(doc) = get_json(http, &url) else {
        return 0;
    };
    doc.get("downloads").and_then(Value::as_i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    const REG: &str = "https://reg.test";
    const DL: &str = "https://dl.test";

    fn fetch(http: &dyn HttpClient, name: &str, version: &str) -> MaintainerSignal {
        fetch_maintainer_signal(http, REG, DL, name, version)
    }

    #[test]
    fn event_stream_handover_shape() {
        // 3.3.6 published by right9ctrl; previous 3.3.5 by dominictarr.
        let packument = br#"{
            "time": {
                "created": "2015-01-01T00:00:00.000Z",
                "3.3.4": "2018-01-01T00:00:00.000Z",
                "3.3.5": "2018-06-01T00:00:00.000Z",
                "3.3.6": "2018-09-09T00:00:00.000Z"
            },
            "versions": {
                "3.3.5": { "_npmUser": { "name": "dominictarr" } },
                "3.3.6": { "_npmUser": { "name": "right9ctrl" } }
            }
        }"#;
        let http = MockHttpClient::new()
            .with(&format!("{REG}/event-stream"), 200, packument.to_vec())
            .with(
                &format!("{DL}/downloads/point/last-week/event-stream"),
                200,
                br#"{"downloads": 2000000}"#.to_vec(),
            );
        let sig = fetch(&http, "event-stream", "3.3.6");
        assert_eq!(sig.publisher, "right9ctrl");
        assert_eq!(sig.previous_version, "3.3.5");
        assert_eq!(sig.previous_publisher, "dominictarr");
        assert_eq!(sig.published_at, "2018-09-09T00:00:00.000Z");
        assert_eq!(sig.weekly_downloads, 2_000_000);
        assert!(!sig.version_unpublished);
    }

    #[test]
    fn yanked_version_marked_unpublished() {
        // time has 1.0.1 but versions does not → published then removed.
        let packument = br#"{
            "time": { "1.0.0": "2020-01-01T00:00:00.000Z", "1.0.1": "2020-02-01T00:00:00.000Z" },
            "versions": { "1.0.0": { "_npmUser": { "name": "alice" } } }
        }"#;
        let http = MockHttpClient::new().with(&format!("{REG}/pkg"), 200, packument.to_vec());
        let sig = fetch(&http, "pkg", "1.0.1");
        assert!(sig.version_unpublished);
        assert_eq!(sig.weekly_downloads, 0); // downloads 404 → 0
    }

    #[test]
    fn scoped_name_encodes_slash() {
        let http = MockHttpClient::new().with(
            &format!("{REG}/@scope%2Fpkg"),
            200,
            br#"{"time":{"1.0.0":"2021-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}}}"#.to_vec(),
        );
        let sig = fetch(&http, "@scope/pkg", "1.0.0");
        assert_eq!(sig.published_at, "2021-01-01T00:00:00.000Z");
    }

    #[test]
    fn missing_packument_returns_empty() {
        let http = MockHttpClient::new(); // 404 everything
        assert_eq!(fetch(&http, "ghost", "9.9.9"), MaintainerSignal::default());
    }

    #[test]
    fn empty_inputs_no_fetch() {
        let http = MockHttpClient::new();
        assert_eq!(fetch(&http, "", "1.0.0"), MaintainerSignal::default());
        assert_eq!(fetch(&http, "pkg", ""), MaintainerSignal::default());
    }

    #[test]
    fn first_publish_has_no_previous() {
        let http = MockHttpClient::new().with(
            &format!("{REG}/new"),
            200,
            br#"{"time":{"1.0.0":"2022-01-01T00:00:00.000Z"},"versions":{"1.0.0":{"_npmUser":{"name":"bob"}}}}"#.to_vec(),
        );
        let sig = fetch(&http, "new", "1.0.0");
        assert_eq!(sig.publisher, "bob");
        assert_eq!(sig.previous_version, "");
        assert_eq!(sig.previous_publisher, "");
    }
}
