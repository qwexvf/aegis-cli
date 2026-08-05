//! Real HTTP transport backed by `ureq` (blocking). A non-2xx status is
//! returned as an [`HttpResponse`], not an error — only transport-level
//! failures produce [`HttpError`], matching the trait contract.

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

pub struct UreqClient {
    agent: ureq::Agent,
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Whole-request budget: DNS, connect, TLS, headers and body.
const TIMEOUT_TOTAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Budget for establishing the TCP connection, across every address tried.
///
/// Must be set explicitly. Left unset, ureq hands connect the *entire* request
/// deadline (`stream.rs`: `connect_deadline` falls back to `unit.deadline`), so
/// an unreachable address eats the whole request and the failure surfaces as
/// `timed out reading response` — ureq's generic deadline message, pointing at a
/// layer that was never reached.
const TIMEOUT_CONNECT: std::time::Duration = std::time::Duration::from_secs(5);

/// How many addresses to offer the connect loop.
///
/// ureq tries addresses sequentially and **halves the remaining budget on every
/// attempt**, so the list length, not the timeout, is what decides whether the
/// last address gets a usable slice. A CDN name routinely resolves to a dozen
/// addresses of one family followed by a dozen of the other
/// (`registry.npmjs.org` returns 24, IPv6 first): twelve dead attempts shrink
/// the budget geometrically and the family that works never gets a turn, no
/// matter how large the timeout. Four — two per family after interleaving —
/// keeps every attempt meaningful.
const MAX_CONNECT_ADDRS: usize = 4;

/// Address list shaping: alternate families, then truncate.
///
/// ureq 2.x has no Happy Eyeballs — no concurrent attempts, no per-family head
/// start — so the only lever is the order and length of the list it is given.
/// Alternating means a host whose IPv6 blackholes pays exactly one dead attempt
/// before reaching IPv4, instead of a dozen.
///
/// The family the OS listed first stays first, so `getaddrinfo`'s RFC 6724
/// sorting still decides the preference; this only stops one family from
/// crowding out the other.
struct InterleavedResolver;

impl ureq::Resolver for InterleavedResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        Ok(interleave_families(
            netloc.to_socket_addrs()?.collect::<Vec<_>>(),
        ))
    }
}

fn interleave_families(addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let (mut first, mut second): (Vec<_>, Vec<_>) = match addrs.first() {
        // Split into "same family as the OS's first choice" and "the other one",
        // preserving the OS's ordering within each.
        Some(head) => {
            let head_is_v4 = head.is_ipv4();
            addrs.iter().partition(|a| a.is_ipv4() == head_is_v4)
        }
        None => return Vec::new(),
    };
    first.reverse();
    second.reverse();

    let mut out = Vec::with_capacity(MAX_CONNECT_ADDRS);
    while out.len() < MAX_CONNECT_ADDRS && !(first.is_empty() && second.is_empty()) {
        if let Some(a) = first.pop() {
            out.push(a);
        }
        if out.len() == MAX_CONNECT_ADDRS {
            break;
        }
        if let Some(a) = second.pop() {
            out.push(a);
        }
    }
    out
}

impl UreqClient {
    pub fn new() -> Self {
        UreqClient {
            agent: ureq::AgentBuilder::new()
                .resolver(InterleavedResolver)
                .timeout_connect(TIMEOUT_CONNECT)
                .timeout(TIMEOUT_TOTAL)
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
    // Snapshot headers before consuming the response into its reader
    // (name lowercased so HttpResponse::header can match case-insensitively).
    let headers: Vec<(String, String)> = resp
        .headers_names()
        .into_iter()
        .filter_map(|name| {
            resp.header(&name)
                .map(|v| (name.to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    let body = read_capped(resp.into_reader())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn v4(n: u8) -> SocketAddr {
        format!("104.16.{n}.34:443").parse().unwrap()
    }
    fn v6(n: u8) -> SocketAddr {
        format!("[2606:4700::6810:{n}22]:443").parse().unwrap()
    }

    /// The bug this exists for: `registry.npmjs.org` resolves to 12 IPv6
    /// addresses followed by 12 IPv4 ones. ureq halves its connect budget on
    /// every attempt, so if IPv6 is blackholed the budget is spent geometrically
    /// on dead addresses and IPv4 never gets a usable slice — at any timeout.
    /// Interleaving means one dead attempt, then the family that works.
    #[test]
    fn one_family_cannot_crowd_out_the_other() {
        let mut addrs: Vec<SocketAddr> = (0..12).map(v6).collect();
        addrs.extend((0..12).map(v4));

        let got = interleave_families(addrs);
        assert_eq!(got.len(), MAX_CONNECT_ADDRS);
        // Second attempt is already the other family.
        assert!(got[0].is_ipv6(), "{got:?}");
        assert!(got[1].is_ipv4(), "{got:?}");
        assert!(got[2].is_ipv6(), "{got:?}");
        assert!(got[3].is_ipv4(), "{got:?}");
    }

    /// `getaddrinfo` already applies RFC 6724 sorting, so whichever family it
    /// put first stays first — this only stops one from monopolising the list.
    #[test]
    fn os_family_preference_is_preserved() {
        let mut v4_first: Vec<SocketAddr> = (0..4).map(v4).collect();
        v4_first.extend((0..4).map(v6));
        let got = interleave_families(v4_first);
        assert!(got[0].is_ipv4(), "{got:?}");
        assert!(got[1].is_ipv6(), "{got:?}");
    }

    /// Order within a family is the OS's, untouched.
    #[test]
    fn within_family_order_is_kept() {
        let addrs = vec![v6(1), v6(2), v6(3), v4(7), v4(8)];
        let got = interleave_families(addrs);
        assert_eq!(got, vec![v6(1), v4(7), v6(2), v4(8)]);
    }

    #[test]
    fn single_family_still_yields_addresses() {
        // A v4-only host must not end up with an empty list.
        let got = interleave_families((0..9).map(v4).collect());
        assert_eq!(got.len(), MAX_CONNECT_ADDRS);
        assert!(got.iter().all(|a| a.is_ipv4()));
        assert_eq!(got[0], v4(0));
    }

    #[test]
    fn short_lists_pass_through_without_padding() {
        assert_eq!(interleave_families(vec![v4(1)]), vec![v4(1)]);
        assert_eq!(interleave_families(vec![v6(1), v4(1)]), vec![v6(1), v4(1)]);
        assert!(interleave_families(Vec::new()).is_empty());
    }

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

    /// Real artifacts that the old 32 MiB cap clipped: pillow 44.8 MiB,
    /// aws-sdk-go 34.4 MiB, klauspost/compress 37.4 MiB.
    #[test]
    fn cap_admits_the_largest_artifacts_in_the_corpus() {
        let pillow_sdist: u64 = 47_025_035;
        assert!(pillow_sdist < MAX_RESPONSE_BYTES);
    }

    /// The connect budget must be bounded independently of the total, or one
    /// unreachable address consumes the entire request.
    #[test]
    fn connect_budget_is_shorter_than_the_total() {
        assert!(TIMEOUT_CONNECT < TIMEOUT_TOTAL);
        // With halving, the fourth attempt still gets a fraction of a second;
        // a longer list would starve it.
        let last_slice = TIMEOUT_CONNECT.as_millis() / 2u128.pow(MAX_CONNECT_ADDRS as u32);
        assert!(last_slice >= 100, "last attempt would get {last_slice}ms");
    }
}
