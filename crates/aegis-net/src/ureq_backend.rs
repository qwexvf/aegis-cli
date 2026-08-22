//! Real HTTP transport backed by `ureq` (blocking). A non-2xx status is
//! returned as an [`HttpResponse`], not an error — only transport-level
//! failures produce [`HttpError`], matching the trait contract.
//!
//! ureq 3 handles connection racing (Happy Eyeballs) and address ordering
//! itself, so the hand-rolled interleaving resolver the 2.x backend needed to
//! stop one IP family from starving the other is gone — the runtime does it.

use crate::{Header, HttpClient, HttpError, HttpResponse};

/// Default outbound User-Agent, mirroring httpx's stamping.
const USER_AGENT: &str = concat!("aegis-cli/", env!("CARGO_PKG_VERSION"));

/// Cap on response body size read into memory.
///
/// Was 32 MiB, inherited from `httpx.MaxJSONResponseBytes` where it only ever
/// guarded JSON. The same client now fetches source archives, and real packages
/// exceed it: pillow's sdist is 44.8 MiB, `aws-sdk-go`'s module zip 34.4 MiB,
/// `klauspost/compress` 37.4 MiB. 128 MiB clears the largest artifact in the
/// corpus with room to spare while still bounding any single response.
const MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;

/// Whole-request budget: DNS, connect, TLS, headers and body.
const TIMEOUT_TOTAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Budget for establishing the TCP connection. Bounded independently of the
/// total so one unreachable address can't consume the whole request deadline.
const TIMEOUT_CONNECT: std::time::Duration = std::time::Duration::from_secs(5);

pub struct UreqClient {
    agent: ureq::Agent,
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UreqClient {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT_TOTAL))
            .timeout_connect(Some(TIMEOUT_CONNECT))
            .user_agent(USER_AGENT)
            // Non-2xx is a valid HTTP response for our purposes, not a transport
            // error — surface it as a response instead of Err.
            .http_status_as_error(false)
            .build();
        UreqClient {
            agent: config.into(),
        }
    }
}

fn into_response(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<HttpResponse, HttpError> {
    let resp = result.map_err(|e| HttpError(e.to_string()))?;
    let status = resp.status().as_u16();
    // Snapshot headers before consuming the body (name lowercased so
    // HttpResponse::header can match case-insensitively).
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    let body = read_capped(resp.into_body().into_reader())?;
    Ok(HttpResponse {
        status,
        body,
        headers,
    })
}

/// Read a body, refusing to return a partial one.
///
/// `take(cap).read_to_end()` stops at the cap and reports success, so an
/// oversized response used to arrive as a 200 with a silently truncated body.
/// Downstream then blamed the wrong layer — a clipped module zip surfaced as
/// `invalid Zip archive: Could not find EOCD` and a clipped sdist as
/// `tar entry: unexpected end of file`, neither of which mentions a size limit.
///
/// Worse than the confusing message: a truncated archive still parses up to the
/// cut, so capabilities living past it are invisible and the package can score
/// clean on partial evidence. Reading one byte past the cap is what makes
/// "too large" distinguishable from "exactly the cap", and it is reported as an
/// error so no caller can mistake a fragment for the whole artifact.
fn read_capped(reader: impl std::io::Read) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    reader
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| HttpError(format!("read body: {e}")))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(HttpError(format!(
            "response exceeds the {} MiB body cap",
            MAX_RESPONSE_BYTES / (1024 * 1024)
        )));
    }
    Ok(body)
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str, headers: &[Header<'_>]) -> Result<HttpResponse, HttpError> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        into_response(req.call())
    }

    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[Header<'_>],
    ) -> Result<HttpResponse, HttpError> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        into_response(req.send(body))
    }
}

use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    /// A body at exactly the cap is whole, so it must come back intact.
    #[test]
    fn body_at_the_cap_is_returned() {
        let body = vec![b'x'; MAX_RESPONSE_BYTES as usize];
        let got = read_capped(std::io::Cursor::new(body)).expect("at the cap is not over it");
        assert_eq!(got.len() as u64, MAX_RESPONSE_BYTES);
    }

    /// The bug this exists for: one byte over the cap used to return Ok with a
    /// truncated body, so a clipped archive was scanned as if it were complete.
    #[test]
    fn oversized_body_errors_instead_of_truncating() {
        let body = vec![b'x'; MAX_RESPONSE_BYTES as usize + 1];
        let err = read_capped(std::io::Cursor::new(body)).expect_err("must not truncate");
        assert!(err.0.contains("body cap"), "{}", err.0);
    }

    /// A body at exactly the cap is whole, so it must come back intact.
    #[test]
    fn connect_budget_is_shorter_than_the_total() {
        assert!(TIMEOUT_CONNECT < TIMEOUT_TOTAL);
    }
}
