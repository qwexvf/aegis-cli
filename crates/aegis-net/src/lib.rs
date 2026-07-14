//! HTTP transport abstraction. Mirrors the role of Go's `httpx` — a
//! thin seam over the real HTTP client so the registry/vuln adapters
//! can be unit-tested offline against a mock.
//!
//! Transport choice differs from the plan's `reqwest`: this uses
//! **`ureq`** (blocking, pure-Rust, no async runtime) because the CLI
//! is blocking + thread-pool concurrent, and dropping tokio keeps the
//! binary small — which matters for the feature-flag/lean-build goal.

use std::collections::HashMap;
use std::sync::Mutex;

/// A completed HTTP response: status code + raw body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A transport-level failure (connection, timeout, DNS). HTTP error
/// *statuses* are not errors here — they come back as an [`HttpResponse`]
/// with a non-2xx `status`, matching how the Go adapters branch on
/// `resp.StatusCode`.
#[derive(Debug, Clone)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HttpError {}

/// One outbound header (name, value).
pub type Header<'a> = (&'a str, &'a str);

/// Blocking HTTP transport. Adapters depend on this trait, not a
/// concrete client, so tests inject [`MockHttpClient`].
pub trait HttpClient {
    fn get(&self, url: &str, headers: &[Header<'_>]) -> Result<HttpResponse, HttpError>;
    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[Header<'_>],
    ) -> Result<HttpResponse, HttpError>;
}

/// In-memory transport for tests: canned responses keyed by URL, plus a
/// recording of every request made. `get`/`post` to an unregistered URL
/// return a synthetic 404.
#[derive(Default)]
pub struct MockHttpClient {
    responses: HashMap<String, HttpResponse>,
    /// (method, url, body) of each call, in order.
    pub calls: Mutex<Vec<(String, String, Vec<u8>)>>,
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a canned response for `url`.
    pub fn with(mut self, url: &str, status: u16, body: impl Into<Vec<u8>>) -> Self {
        self.responses.insert(
            url.to_string(),
            HttpResponse {
                status,
                body: body.into(),
            },
        );
        self
    }

    fn respond(&self, method: &str, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        self.calls
            .lock()
            .unwrap()
            .push((method.to_string(), url.to_string(), body.to_vec()));
        Ok(self.responses.get(url).cloned().unwrap_or(HttpResponse {
            status: 404,
            body: Vec::new(),
        }))
    }
}

impl HttpClient for MockHttpClient {
    fn get(&self, url: &str, _headers: &[Header<'_>]) -> Result<HttpResponse, HttpError> {
        self.respond("GET", url, &[])
    }
    fn post(
        &self,
        url: &str,
        body: &[u8],
        _headers: &[Header<'_>],
    ) -> Result<HttpResponse, HttpError> {
        self.respond("POST", url, body)
    }
}

#[cfg(feature = "ureq-backend")]
mod ureq_backend;
#[cfg(feature = "ureq-backend")]
pub use ureq_backend::UreqClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_canned_and_records_calls() {
        let client = MockHttpClient::new().with("https://x/api", 200, b"hello".to_vec());
        let resp = client.post("https://x/api", b"query", &[]).unwrap();
        assert!(resp.is_ok());
        assert_eq!(resp.body, b"hello");

        let miss = client.get("https://x/missing", &[]).unwrap();
        assert_eq!(miss.status, 404);

        let calls = client.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            ("POST".into(), "https://x/api".into(), b"query".to_vec())
        );
    }
}
