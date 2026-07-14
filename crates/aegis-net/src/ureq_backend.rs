//! Real HTTP transport backed by `ureq` (blocking). A non-2xx status is
//! returned as an [`HttpResponse`], not an error — only transport-level
//! failures produce [`HttpError`], matching the trait contract.

use crate::{Header, HttpClient, HttpError, HttpResponse};

/// Default outbound User-Agent, mirroring httpx's stamping.
const USER_AGENT: &str = concat!("aegis-cli/", env!("CARGO_PKG_VERSION"));

/// Cap on response body size read into memory (mirrors
/// `httpx.MaxJSONResponseBytes`): 32 MiB.
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

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
        UreqClient {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent(USER_AGENT)
                .build(),
        }
    }
}

fn into_response(result: Result<ureq::Response, ureq::Error>) -> Result<HttpResponse, HttpError> {
    let resp = match result {
        Ok(r) => r,
        // ureq surfaces non-2xx as Error::Status — that's a valid HTTP
        // response for our purposes, not a transport failure.
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(HttpError(e.to_string())),
    };
    let status = resp.status();
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| HttpError(format!("read body: {e}")))?;
    Ok(HttpResponse { status, body })
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str, headers: &[Header<'_>]) -> Result<HttpResponse, HttpError> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.set(k, v);
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
            req = req.set(k, v);
        }
        into_response(req.send_bytes(body))
    }
}

use std::io::Read;
