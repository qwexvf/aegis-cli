//! Record/replay HTTP transport — deterministic offline parity gates.
//!
//! [`crate::default_client`] swaps the live `ureq` transport for one of these
//! when an env var points at a cassette directory:
//!
//! - `AEGIS_HTTP_RECORD=<dir>` — wrap the real client, persist every response
//!   as a cassette file (used once, with network, to capture a fixture).
//! - `AEGIS_HTTP_REPLAY=<dir>` — serve responses from `<dir>`, never touch the
//!   network. This is what the offline `ci-parity` CI gate runs.
//!
//! Requests are keyed by `FNV-1a(method | url | body)` so a POST body (the OSV
//! and EPSS batch queries) selects the right canned response, not just the URL.
//! Replaying an *unrecorded* request is a hard error — a cassette gap fails
//! loud, so the fixture gets re-recorded rather than silently diverging.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{Header, HttpClient, HttpError, HttpResponse};

/// One cassette entry on disk. `method`/`url` are stored for human debugging;
/// the lookup key is derived from `(method, url, body)`, not read back.
#[derive(Serialize, Deserialize)]
struct Entry {
    method: String,
    url: String,
    status: u16,
    headers: Vec<(String, String)>,
    /// Body base64-encoded — responses include binary tarballs.
    body_b64: String,
}

/// FNV-1a 64-bit. Not cryptographic — just a stable, dependency-free key for a
/// handful of recorded requests (collision odds are negligible at this scale).
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Cassette filename stem for a request. Includes the body so batch POSTs with
/// distinct query sets map to distinct files.
fn cassette_key(method: &str, url: &str, body: &[u8]) -> String {
    let mut buf = Vec::with_capacity(method.len() + url.len() + body.len() + 2);
    buf.extend_from_slice(method.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(url.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(body);
    format!("{:016x}", fnv1a(&buf))
}

// ── replay ───────────────────────────────────────────────────────────────────

/// Serves recorded responses from a directory; never touches the network. A
/// miss is a hard error so an incomplete cassette fails the gate loudly.
pub struct ReplayClient {
    dir: PathBuf,
}

impl ReplayClient {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn lookup(&self, method: &str, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        let key = cassette_key(method, url, body);
        let path = self.dir.join(format!("{key}.json"));
        let raw = std::fs::read(&path).map_err(|e| {
            HttpError(format!(
                "cassette miss: {method} {url} (key {key}: {e}) — re-record with AEGIS_HTTP_RECORD"
            ))
        })?;
        let entry: Entry = serde_json::from_slice(&raw)
            .map_err(|e| HttpError(format!("cassette {key} parse: {e}")))?;
        let body = B64
            .decode(entry.body_b64.as_bytes())
            .map_err(|e| HttpError(format!("cassette {key} body decode: {e}")))?;
        Ok(HttpResponse {
            status: entry.status,
            body,
            headers: entry.headers,
        })
    }
}

impl HttpClient for ReplayClient {
    fn get(&self, url: &str, _headers: &[Header<'_>]) -> Result<HttpResponse, HttpError> {
        self.lookup("GET", url, &[])
    }
    fn post(
        &self,
        url: &str,
        body: &[u8],
        _headers: &[Header<'_>],
    ) -> Result<HttpResponse, HttpError> {
        self.lookup("POST", url, body)
    }
}

// ── record ─────────────────────────────────────────────────────────────────

/// Wraps a real transport and persists each response into a cassette dir. Used
/// once (with network) to capture a fixture; safe under concurrent (rayon)
/// enrich because writes go through [`crate::atomic_write`] with unique temps.
pub struct RecordClient {
    dir: PathBuf,
    inner: Box<dyn HttpClient>,
}

impl RecordClient {
    pub fn new(dir: impl Into<PathBuf>, inner: Box<dyn HttpClient>) -> Self {
        Self {
            dir: dir.into(),
            inner,
        }
    }

    fn record(&self, method: &str, url: &str, body: &[u8], resp: &HttpResponse) {
        let _ = std::fs::create_dir_all(&self.dir);
        let entry = Entry {
            method: method.to_string(),
            url: url.to_string(),
            status: resp.status,
            headers: resp.headers.clone(),
            body_b64: B64.encode(&resp.body),
        };
        if let Ok(json) = serde_json::to_vec_pretty(&entry) {
            let key = cassette_key(method, url, body);
            let _ = crate::atomic_write(&self.dir.join(format!("{key}.json")), &json);
        }
    }
}

impl HttpClient for RecordClient {
    fn get(&self, url: &str, headers: &[Header<'_>]) -> Result<HttpResponse, HttpError> {
        let resp = self.inner.get(url, headers)?;
        self.record("GET", url, &[], &resp);
        Ok(resp)
    }
    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[Header<'_>],
    ) -> Result<HttpResponse, HttpError> {
        let resp = self.inner.post(url, body, headers)?;
        self.record("POST", url, body, &resp);
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockHttpClient;

    #[test]
    fn record_then_replay_roundtrips() {
        let dir = std::env::temp_dir().join(format!("aegis-cassette-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mock = MockHttpClient::new()
            .with("https://x/meta", 200, b"\x00\x01binary".to_vec())
            .with("https://x/batch", 200, b"resp-b".to_vec());

        // record
        let rec = RecordClient::new(&dir, Box::new(mock));
        let g = rec.get("https://x/meta", &[]).unwrap();
        assert_eq!(g.body, b"\x00\x01binary");
        rec.post("https://x/batch", b"query-a", &[]).unwrap();

        // replay serves the same bytes, offline
        let rep = ReplayClient::new(&dir);
        assert_eq!(
            rep.get("https://x/meta", &[]).unwrap().body,
            b"\x00\x01binary"
        );
        assert_eq!(
            rep.post("https://x/batch", b"query-a", &[]).unwrap().body,
            b"resp-b"
        );

        // a POST with a different body is a distinct (missing) key → hard error
        assert!(rep.post("https://x/batch", b"query-b", &[]).is_err());
        // an unrecorded URL is a hard error, not a silent 404
        assert!(rep.get("https://x/never", &[]).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_depends_on_method_url_and_body() {
        let a = cassette_key("GET", "https://x", b"");
        let b = cassette_key("POST", "https://x", b"");
        let c = cassette_key("GET", "https://y", b"");
        let d = cassette_key("POST", "https://x", b"body");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, d);
    }
}
