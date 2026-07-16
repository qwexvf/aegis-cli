//! npm provenance/attestations. Port of `internal/infra/npmattestations/client.go`.
//!
//! One GET against the registry attestations endpoint tells us whether an npm
//! `name@version` has a published provenance attestation. When a SLSA v1
//! predicate is present its DSSE payload is base64-decoded and the source repo
//! and git commit are lifted out; a publish-only attestation still counts as
//! provenance but carries no source. Everything is best-effort — a 404,
//! transport error, or unparseable body degrades to "no provenance", never a
//! panic. Cryptographic signature verification (sigstore) is out of scope.

use aegis_net::HttpClient;
use serde_json::Value;

/// The npm registry base (attestations host).
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// SLSA Provenance v1 predicate URI — carries build repo + git commit SHA in
/// `buildDefinition`. The other predicate the registry emits is the npm
/// publish attestation (`.../specs/publish/v0.1`), which confirms the package
/// came from the npm CLI but carries no source repo or commit; anything that
/// isn't SLSA v1 collapses into the publish-only branch below.
const SLSA_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// Structured outcome of one npm attestation lookup. `has_provenance` is the
/// collapsed signal (Go's `Status == "attested"`); `source_uri` and `commit`
/// are only non-empty when a SLSA v1 predicate was found. Mirrors Go's
/// `usecase.ProvenanceResult`, with "missing"/"error" folded into
/// `has_provenance: false` since the lookup is best-effort.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenanceStatus {
    pub has_provenance: bool,
    pub source_uri: String,
    pub commit: String,
}

/// Fetches the npm provenance attestation for `name@version`. `base` is
/// injectable for tests. Returns `ProvenanceStatus::default()` (no provenance)
/// on empty inputs, a 404, any transport/HTTP error, or an unparseable body —
/// absence is read as "no provenance", never as an error.
pub fn fetch_provenance(
    http: &dyn HttpClient,
    base: &str,
    name: &str,
    version: &str,
) -> ProvenanceStatus {
    if name.is_empty() || version.is_empty() {
        return ProvenanceStatus::default();
    }
    let url = format!(
        "{base}/-/npm/v1/attestations/{}",
        encode_package_id(name, version)
    );
    let Ok(resp) = http.get(&url, &[]) else {
        return ProvenanceStatus::default();
    };
    if !resp.is_ok() {
        // 404 = no attestation; any other non-2xx = error → no provenance.
        return ProvenanceStatus::default();
    }
    let Ok(doc) = serde_json::from_slice::<Value>(&resp.body) else {
        return ProvenanceStatus::default();
    };
    parse_attestation_response(&doc)
}

/// Path segment for `name@version`. Scoped packages (`@scope/pkg`) encode the
/// slash as `%2F` so the registry treats the whole name as one path component.
fn encode_package_id(name: &str, version: &str) -> String {
    let encoded = if name.starts_with('@') {
        name.replacen('/', "%2F", 1)
    } else {
        name.to_string()
    };
    format!("{encoded}@{version}")
}

/// Extract provenance metadata from the parsed registry response. Prefers the
/// SLSA v1 predicate (source + commit) over publish-only; falls through to
/// "has provenance, no source" when only publish/unknown predicates exist.
fn parse_attestation_response(doc: &Value) -> ProvenanceStatus {
    let attestations = match doc.get("attestations").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => return ProvenanceStatus::default(),
    };

    // Prefer the SLSA v1 predicate — it carries source repo + git SHA.
    for att in attestations {
        if att.get("predicateType").and_then(Value::as_str) != Some(SLSA_PREDICATE_TYPE) {
            continue;
        }
        let Some(payload) = att
            .get("bundle")
            .and_then(|b| b.get("dsseEnvelope"))
            .and_then(|e| e.get("payload"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(raw) = base64_decode(payload) else {
            continue; // malformed — try next entry
        };
        let Ok(stmt) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        let workflow = stmt
            .get("predicate")
            .and_then(|p| p.get("buildDefinition"))
            .and_then(|b| b.get("externalParameters"))
            .and_then(|e| e.get("workflow"));
        let source_uri = workflow
            .and_then(|w| w.get("repository"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let commit = workflow
            .and_then(|w| w.get("sha"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        return ProvenanceStatus {
            has_provenance: true,
            source_uri,
            commit,
        };
    }

    // No SLSA v1. A publish attestation still counts as provenance (came from
    // the npm CLI, no git-level build provenance). Unknown predicate types are
    // treated as attested too — conservative, matching the Go client.
    ProvenanceStatus {
        has_provenance: true,
        source_uri: String::new(),
        commit: String::new(),
    }
}

/// Decode standard base64 (RFC 4648, with padding). `None` on any invalid
/// character or malformed length — callers treat that as a skipped entry.
/// Kept in-tree to avoid pulling a base64 crate for one DSSE payload.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.trim().as_bytes();
    let stripped: &[u8] = match bytes.iter().position(|&b| b == b'=') {
        // Padding, if present, must sit at the tail and only be '='.
        Some(p) if bytes[p..].iter().all(|&b| b == b'=') => &bytes[..p],
        Some(_) => return None,
        None => bytes,
    };
    if stripped.len() % 4 == 1 {
        return None; // impossible group length
    }
    let mut out = Vec::with_capacity(stripped.len() / 4 * 3);
    for chunk in stripped.chunks(4) {
        let mut acc = 0u32;
        for &b in chunk {
            acc = (acc << 6) | val(b)? as u32;
        }
        // A partial final chunk of n sextets yields n-1 bytes.
        acc <<= 6 * (4 - chunk.len());
        let n = chunk.len() - 1;
        for i in 0..n {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    const BASE: &str = "https://reg.test";
    const PUBLISH_PREDICATE_TYPE: &str =
        "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";

    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut acc = 0u32;
            for i in 0..3 {
                acc |= (*chunk.get(i).unwrap_or(&0) as u32) << (16 - 8 * i);
            }
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(A[((acc >> (18 - 6 * i)) & 0x3f) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn slsa_payload(repo: &str, sha: &str) -> String {
        let stmt = format!(
            r#"{{"predicateType":"{SLSA_PREDICATE_TYPE}","predicate":{{"buildDefinition":{{"externalParameters":{{"workflow":{{"repository":"{repo}","sha":"{sha}","ref":"refs/heads/main"}}}}}}}}}}"#
        );
        b64(stmt.as_bytes())
    }

    fn publish_payload() -> String {
        b64(br#"{"predicate":{"name":"test-pkg","version":"1.0.0"}}"#)
    }

    fn attestations_url(pkg_id: &str) -> String {
        format!("{BASE}/-/npm/v1/attestations/{pkg_id}")
    }

    #[test]
    fn slsa_v1_yields_source_and_commit() {
        let body = format!(
            r#"{{"attestations":[{{"predicateType":"{SLSA_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}}]}}"#,
            slsa_payload("https://github.com/owner/repo", "abc123")
        );
        let http = MockHttpClient::new().with(&attestations_url("test-pkg@1.0.0"), 200, body);
        let res = fetch_provenance(&http, BASE, "test-pkg", "1.0.0");
        assert!(res.has_provenance);
        assert_eq!(res.source_uri, "https://github.com/owner/repo");
        assert_eq!(res.commit, "abc123");
    }

    #[test]
    fn publish_only_still_has_provenance_without_source() {
        let body = format!(
            r#"{{"attestations":[{{"predicateType":"{PUBLISH_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}}]}}"#,
            publish_payload()
        );
        let http = MockHttpClient::new().with(&attestations_url("test-pkg@1.0.0"), 200, body);
        let res = fetch_provenance(&http, BASE, "test-pkg", "1.0.0");
        assert!(res.has_provenance);
        assert_eq!(res.source_uri, "");
        assert_eq!(res.commit, "");
    }

    #[test]
    fn missing_attestation_404_is_no_provenance() {
        let http = MockHttpClient::new(); // 404 everything
        let res = fetch_provenance(&http, BASE, "no-attest-pkg", "1.0.0");
        assert_eq!(res, ProvenanceStatus::default());
        assert!(!res.has_provenance);
    }

    #[test]
    fn empty_attestations_array_is_no_provenance() {
        let http = MockHttpClient::new().with(
            &attestations_url("empty-pkg@1.0.0"),
            200,
            br#"{"attestations":[]}"#.to_vec(),
        );
        let res = fetch_provenance(&http, BASE, "empty-pkg", "1.0.0");
        assert!(!res.has_provenance);
    }

    #[test]
    fn http_500_is_no_provenance() {
        let http = MockHttpClient::new().with(&attestations_url("bad-pkg@1.0.0"), 500, Vec::new());
        let res = fetch_provenance(&http, BASE, "bad-pkg", "1.0.0");
        assert!(!res.has_provenance);
    }

    #[test]
    fn malformed_slsa_base64_falls_through_to_publish() {
        let body = format!(
            r#"{{"attestations":[{{"predicateType":"{SLSA_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"!!!not-base64!!!"}}}}}},{{"predicateType":"{PUBLISH_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}}]}}"#,
            publish_payload()
        );
        let http = MockHttpClient::new().with(&attestations_url("pkg@1.0.0"), 200, body);
        let res = fetch_provenance(&http, BASE, "pkg", "1.0.0");
        assert!(res.has_provenance);
        assert_eq!(res.source_uri, "");
    }

    #[test]
    fn slsa_preferred_over_publish_regardless_of_order() {
        let body = format!(
            r#"{{"attestations":[{{"predicateType":"{PUBLISH_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}},{{"predicateType":"{SLSA_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}}]}}"#,
            publish_payload(),
            slsa_payload("https://github.com/a/b", "def456")
        );
        let http = MockHttpClient::new().with(&attestations_url("pkg@1.0.0"), 200, body);
        let res = fetch_provenance(&http, BASE, "pkg", "1.0.0");
        assert_eq!(res.source_uri, "https://github.com/a/b");
        assert_eq!(res.commit, "def456");
    }

    #[test]
    fn scoped_name_encodes_slash() {
        // @scope/pkg@1.0.0 → /-/npm/v1/attestations/@scope%2Fpkg@1.0.0
        let body = format!(
            r#"{{"attestations":[{{"predicateType":"{PUBLISH_PREDICATE_TYPE}","bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}}]}}"#,
            publish_payload()
        );
        let http = MockHttpClient::new().with(&attestations_url("@scope%2Fpkg@1.0.0"), 200, body);
        let res = fetch_provenance(&http, BASE, "@scope/pkg", "1.0.0");
        assert!(res.has_provenance);
    }

    #[test]
    fn bad_json_is_no_provenance() {
        let http =
            MockHttpClient::new().with(&attestations_url("pkg@1.0.0"), 200, b"{invalid".to_vec());
        let res = fetch_provenance(&http, BASE, "pkg", "1.0.0");
        assert!(!res.has_provenance);
    }

    #[test]
    fn empty_inputs_make_no_request() {
        let http = MockHttpClient::new();
        assert_eq!(
            fetch_provenance(&http, BASE, "", "1.0.0"),
            ProvenanceStatus::default()
        );
        assert_eq!(
            fetch_provenance(&http, BASE, "pkg", ""),
            ProvenanceStatus::default()
        );
        assert!(http.calls.lock().unwrap().is_empty());
    }
}
