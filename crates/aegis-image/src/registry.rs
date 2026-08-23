//! OCI/Docker registry pull — fetch an image by `repo:tag` reference instead
//! of from a local tarball, anonymously or with credentials.
//!
//! Walks the standard OCI distribution flow — parse the reference, resolve a
//! bearer token (see Auth below), fetch the manifest (following a multi-arch
//! index to its linux/amd64 child), then fetch every layer blob — and feeds
//! the ordered gzipped layer blobs into the exact same
//! the `overlay::overlay_layers` assembly the tarball path uses, so
//! whiteouts and later-layer-wins semantics are identical.
//!
//! ## Auth
//!
//! One generic OCI token flow handles every registry (docker.io, ghcr.io,
//! GCR, private repos): ping `GET /v2/`, and if it answers `401` with a
//! `Www-Authenticate: Bearer realm=…,service=…[,scope=…]` challenge, fetch a
//! bearer token from the challenge's realm and send it on every subsequent
//! request. A `2xx` ping means no auth is needed (fully public) and we pull
//! anonymously.
//!
//! [`Credentials`] (from `--username/--password` or the `AEGIS_REGISTRY_USER`
//! / `AEGIS_REGISTRY_PASS` env vars) are sent as HTTP Basic auth on the token
//! request, so **private images** work. Without credentials the same flow
//! fetches an anonymous token — the public-pull path. Any HTTP/parse failure
//! returns `Err(String)` — never panics.

use serde::Deserialize;

use aegis_net::HttpClient;

use crate::overlay::{overlay_layers, ImageFiles};

/// Default registry for a bare reference (`alpine`, `library/nginx`).
const DEFAULT_REGISTRY: &str = "registry-1.docker.io";
/// Media types we accept when asking for a manifest. Includes the multi-arch
/// index types so the registry hands back an index for a multi-platform tag.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json";

/// A parsed image reference: `<registry>/<name>:<tag>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host, e.g. `registry-1.docker.io` or `ghcr.io`.
    pub registry: String,
    /// Repository name including namespace, e.g. `library/alpine`, `owner/repo`.
    pub name: String,
    /// Tag, e.g. `latest`, `1.2`.
    pub tag: String,
}

/// Parse `[registry/]namespace/repo[:tag]` into an [`ImageRef`].
///
/// Rules:
///   - default registry `registry-1.docker.io`;
///   - the first `/`-segment is treated as a registry host when it contains a
///     `.` or `:`, or is exactly `localhost`; otherwise it's part of the name;
///   - a single-name Docker Hub ref (`alpine`) gets the `library/` namespace;
///   - default tag `latest`.
///
/// A trailing `@sha256:...` digest is stripped and ignored for this slice.
pub fn parse_reference(reference: &str) -> Result<ImageRef, String> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Err("image: empty reference".to_string());
    }
    // Drop an optional `@digest` suffix — pin-by-digest isn't in this slice.
    let reference = match reference.split_once('@') {
        Some((head, _)) => head,
        None => reference,
    };

    // Separate the tag. The tag can only live in the last `/`-segment; a `:` in
    // an earlier segment is a registry port, not a tag delimiter.
    let (path_part, tag) = match reference.rsplit_once('/') {
        Some((prefix, last)) => match last.split_once(':') {
            Some((seg, tag)) => (format!("{prefix}/{seg}"), tag.to_string()),
            None => (reference.to_string(), "latest".to_string()),
        },
        None => match reference.split_once(':') {
            Some((seg, tag)) => (seg.to_string(), tag.to_string()),
            None => (reference.to_string(), "latest".to_string()),
        },
    };
    if tag.is_empty() {
        return Err(format!("image: empty tag in reference {reference:?}"));
    }

    let first = path_part.split('/').next().unwrap_or("");
    let is_registry = first.contains('.') || first.contains(':') || first == "localhost";
    let (registry, name) = if is_registry {
        let name = path_part[first.len()..].trim_start_matches('/').to_string();
        (first.to_string(), name)
    } else if path_part.contains('/') {
        (DEFAULT_REGISTRY.to_string(), path_part.clone())
    } else {
        // Bare single name on Docker Hub → official `library/` namespace.
        (DEFAULT_REGISTRY.to_string(), format!("library/{path_part}"))
    };
    if name.is_empty() {
        return Err(format!(
            "image: no repository name in reference {reference:?}"
        ));
    }
    Ok(ImageRef {
        registry,
        name,
        tag,
    })
}

/// Docker Hub token response (`token`, or `access_token` on some flows).
#[derive(Deserialize, Default)]
struct TokenResponse {
    #[serde(default)]
    token: String,
    #[serde(rename = "access_token", default)]
    access_token: String,
}

/// A manifest (single-arch) or manifest index (multi-arch). We parse both into
/// one struct: an index populates `manifests`, a single manifest `layers`.
#[derive(Deserialize, Default)]
struct RawManifest {
    #[serde(default)]
    manifests: Vec<PlatformDescriptor>,
    #[serde(default)]
    layers: Vec<BlobDescriptor>,
}

/// One entry of a manifest index: a per-platform child manifest.
#[derive(Deserialize)]
struct PlatformDescriptor {
    #[serde(default)]
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

/// One layer descriptor inside a single-arch manifest.
#[derive(Deserialize)]
struct BlobDescriptor {
    #[serde(default)]
    digest: String,
}

/// Registry credentials for a private pull (HTTP Basic on the token request).
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// A parsed `Www-Authenticate: Bearer …` challenge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct BearerChallenge {
    realm: String,
    service: String,
    scope: String,
}

/// Pull an image by reference (anonymous) and return its flattened root
/// filesystem. Convenience wrapper over [`pull_image_auth`] with no creds.
pub fn pull_image(http: &dyn HttpClient, reference: &str) -> Result<ImageFiles, String> {
    pull_image_auth(http, reference, None)
}

/// Pull an image by reference, optionally authenticated, and return its
/// flattened root filesystem.
///
/// Resolves a bearer token via the generic `/v2/` challenge flow (sending
/// `creds` as Basic auth when present), then feeds the ordered gzipped layer
/// blobs into the shared `overlay::overlay_layers` assembly —
/// identical whiteout / later-layer-wins semantics to the tarball path.
pub fn pull_image_auth(
    http: &dyn HttpClient,
    reference: &str,
    creds: Option<&Credentials>,
) -> Result<ImageFiles, String> {
    let r = parse_reference(reference)?;
    let token = acquire_token(http, &r, creds)?;

    let manifest_bytes = get_manifest(http, &r, token.as_deref(), &r.tag)?;
    let layer_digests = resolve_layers(http, &r, token.as_deref(), &manifest_bytes)?;
    if layer_digests.is_empty() {
        return Err(format!("image: manifest for {reference} has no layers"));
    }

    let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(layer_digests.len());
    for digest in &layer_digests {
        blobs.push(get_blob(http, &r, token.as_deref(), digest)?);
    }
    let slices: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    overlay_layers(&slices)
}

/// Resolve a bearer token for `r` via the OCI `/v2/` ping. A `2xx` ping means
/// no auth is needed (`Ok(None)`); a `401` with a Bearer challenge triggers a
/// token fetch from its realm. Any other ping outcome falls back to an
/// anonymous pull (`Ok(None)`) — the manifest GET then surfaces a clear error
/// if a token was actually required.
fn acquire_token(
    http: &dyn HttpClient,
    r: &ImageRef,
    creds: Option<&Credentials>,
) -> Result<Option<String>, String> {
    let ping_url = format!("https://{}/v2/", r.registry);
    let resp = http
        .get(&ping_url, &[])
        .map_err(|e| format!("image: ping GET {ping_url}: {e}"))?;
    if resp.is_ok() {
        return Ok(None);
    }
    if resp.status != 401 {
        return Ok(None);
    }
    let Some(challenge) = resp
        .header("www-authenticate")
        .and_then(parse_bearer_challenge)
    else {
        return Ok(None);
    };
    fetch_token(http, r, &challenge, creds).map(Some)
}

/// Parse a `Www-Authenticate` value into a [`BearerChallenge`]. Returns `None`
/// unless it's a `Bearer` scheme with at least a `realm`.
fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let rest = header.trim().strip_prefix("Bearer ").or_else(|| {
        // Case-insensitive scheme check for non-canonical casing.
        header
            .trim()
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("Bearer "))
            .map(|_| &header.trim()[7..])
    })?;
    let mut c = BearerChallenge::default();
    for part in split_challenge_params(rest) {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "realm" => c.realm = value.to_string(),
            "service" => c.service = value.to_string(),
            "scope" => c.scope = value.to_string(),
            _ => {}
        }
    }
    (!c.realm.is_empty()).then_some(c)
}

/// Split `key="v,v",key2=v2` on commas that sit outside double quotes.
fn split_challenge_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Fetch a bearer token from the challenge realm for a pull scope. Uses the
/// challenge's own scope, else defaults to `repository:{name}:pull`. Sends
/// Basic auth when `creds` are present (private pull).
fn fetch_token(
    http: &dyn HttpClient,
    r: &ImageRef,
    challenge: &BearerChallenge,
    creds: Option<&Credentials>,
) -> Result<String, String> {
    let scope = if challenge.scope.is_empty() {
        format!("repository:{}:pull", r.name)
    } else {
        challenge.scope.clone()
    };
    let sep = if challenge.realm.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = if challenge.service.is_empty() {
        format!("{}{sep}scope={scope}", challenge.realm)
    } else {
        format!(
            "{}{sep}service={}&scope={scope}",
            challenge.realm, challenge.service
        )
    };

    let basic = creds.map(|c| {
        format!(
            "Basic {}",
            base64_encode(format!("{}:{}", c.username, c.password).as_bytes())
        )
    });
    let headers: Vec<(&str, &str)> = match basic.as_deref() {
        Some(a) => vec![("Authorization", a)],
        None => Vec::new(),
    };
    let resp = http
        .get(&url, &headers)
        .map_err(|e| format!("image: token GET {url}: {e}"))?;
    if !resp.is_ok() {
        return Err(format!("image: token GET {url}: status {}", resp.status));
    }
    let parsed: TokenResponse =
        serde_json::from_slice(&resp.body).map_err(|e| format!("image: parse token: {e}"))?;
    let token = if parsed.token.is_empty() {
        parsed.access_token
    } else {
        parsed.token
    };
    if token.is_empty() {
        return Err("image: registry returned an empty token".to_string());
    }
    Ok(token)
}

/// Standard-alphabet base64 encode (for the Basic-auth header). Hand-rolled to
/// avoid a dependency, matching the crate's no-extra-deps convention.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// GET a manifest by tag or digest reference.
fn get_manifest(
    http: &dyn HttpClient,
    r: &ImageRef,
    token: Option<&str>,
    reference: &str,
) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://{}/v2/{}/manifests/{}",
        r.registry, r.name, reference
    );
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = vec![("Accept", MANIFEST_ACCEPT)];
    if let Some(a) = auth.as_deref() {
        headers.push(("Authorization", a));
    }
    let resp = http
        .get(&url, &headers)
        .map_err(|e| format!("image: manifest GET {url}: {e}"))?;
    if !resp.is_ok() {
        return Err(format!("image: manifest GET {url}: status {}", resp.status));
    }
    Ok(resp.body)
}

/// Turn manifest bytes into an ordered layer-digest list, following a multi-arch
/// index to its linux/amd64 child manifest if needed.
fn resolve_layers(
    http: &dyn HttpClient,
    r: &ImageRef,
    token: Option<&str>,
    manifest_bytes: &[u8],
) -> Result<Vec<String>, String> {
    let raw: RawManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("image: parse manifest: {e}"))?;

    if !raw.manifests.is_empty() {
        // Manifest index: pick the linux/amd64 child and fetch it.
        let pick = raw
            .manifests
            .iter()
            .find(|d| {
                d.platform
                    .as_ref()
                    .is_some_and(|p| p.os == "linux" && p.architecture == "amd64")
            })
            .ok_or_else(|| "image: manifest index has no linux/amd64 entry".to_string())?;
        if pick.digest.is_empty() {
            return Err("image: linux/amd64 index entry has no digest".to_string());
        }
        let child = get_manifest(http, r, token, &pick.digest)?;
        let inner: RawManifest = serde_json::from_slice(&child)
            .map_err(|e| format!("image: parse amd64 manifest: {e}"))?;
        return Ok(inner.layers.into_iter().map(|l| l.digest).collect());
    }

    Ok(raw.layers.into_iter().map(|l| l.digest).collect())
}

/// GET a single layer blob by digest → gzipped layer tar bytes.
fn get_blob(
    http: &dyn HttpClient,
    r: &ImageRef,
    token: Option<&str>,
    digest: &str,
) -> Result<Vec<u8>, String> {
    let url = format!("https://{}/v2/{}/blobs/{}", r.registry, r.name, digest);
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(a) = auth.as_deref() {
        headers.push(("Authorization", a));
    }
    let resp = http
        .get(&url, &headers)
        .map_err(|e| format!("image: blob GET {url}: {e}"))?;
    if !resp.is_ok() {
        return Err(format!("image: blob GET {url}: status {}", resp.status));
    }
    Ok(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use aegis_net::MockHttpClient;

    fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, name, *body).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn parse_bare_name_defaults_to_library_latest() {
        let r = parse_reference("alpine").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_bare_name_with_tag() {
        let r = parse_reference("nginx:1.25").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.name, "library/nginx");
        assert_eq!(r.tag, "1.25");
    }

    #[test]
    fn parse_namespaced_docker_hub_ref() {
        let r = parse_reference("bitnami/redis:7").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.name, "bitnami/redis");
        assert_eq!(r.tag, "7");
    }

    #[test]
    fn parse_ghcr_ref() {
        let r = parse_reference("ghcr.io/o/r:1.2").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "o/r");
        assert_eq!(r.tag, "1.2");
    }

    #[test]
    fn parse_ghcr_ref_defaults_tag() {
        let r = parse_reference("ghcr.io/owner/repo").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "owner/repo");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_empty_reference_errors() {
        assert!(parse_reference("   ").is_err());
    }

    #[test]
    fn pull_single_arch_manifest_merges_layers() {
        let token_url =
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull";
        let manifest_url = "https://registry-1.docker.io/v2/library/alpine/manifests/latest";
        let blob_a = "https://registry-1.docker.io/v2/library/alpine/blobs/sha256:aaa";
        let blob_b = "https://registry-1.docker.io/v2/library/alpine/blobs/sha256:bbb";

        // Layer A ships a file that layer B whites out, plus one that survives.
        let layer_a = gzip(&make_tar(&[
            ("app/gone.txt", b"remove me"),
            ("app/keep.txt", b"base"),
        ]));
        // Layer B whites out gone.txt and overrides keep.txt.
        let layer_b = gzip(&make_tar(&[
            ("app/.wh.gone.txt", b""),
            ("app/keep.txt", b"top"),
        ]));

        let manifest = r#"{"schemaVersion":2,"layers":[
            {"digest":"sha256:aaa"},{"digest":"sha256:bbb"}]}"#;

        let http = MockHttpClient::new()
            .with(token_url, 200, br#"{"token":"tok123"}"#.to_vec())
            .with(manifest_url, 200, manifest.as_bytes().to_vec())
            .with(blob_a, 200, layer_a)
            .with(blob_b, 200, layer_b);

        let files = pull_image(&http, "alpine").expect("pull");

        assert!(
            !files.files.contains_key("app/gone.txt"),
            "whiteout should remove app/gone.txt"
        );
        assert_eq!(
            files.files.get("app/keep.txt").map(Vec::as_slice),
            Some(&b"top"[..]),
            "later layer should win"
        );
    }

    #[test]
    fn pull_manifest_list_selects_amd64() {
        let token_url =
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull";
        let manifest_url = "https://registry-1.docker.io/v2/library/alpine/manifests/latest";
        // Child manifests fetched by digest.
        let amd64_url = "https://registry-1.docker.io/v2/library/alpine/manifests/sha256:amd64man";
        let amd64_blob = "https://registry-1.docker.io/v2/library/alpine/blobs/sha256:amd64layer";
        let arm_blob = "https://registry-1.docker.io/v2/library/alpine/blobs/sha256:armlayer";

        let index = r#"{"schemaVersion":2,"manifests":[
            {"digest":"sha256:armman","platform":{"architecture":"arm64","os":"linux"}},
            {"digest":"sha256:amd64man","platform":{"architecture":"amd64","os":"linux"}}]}"#;
        let amd64_manifest = r#"{"schemaVersion":2,"layers":[{"digest":"sha256:amd64layer"}]}"#;

        let amd64_layer = gzip(&make_tar(&[("app/arch.txt", b"amd64")]));
        // Register an arm blob too so a wrong selection would produce arm content.
        let arm_layer = gzip(&make_tar(&[("app/arch.txt", b"arm64")]));

        let http = MockHttpClient::new()
            .with(token_url, 200, br#"{"token":"tok"}"#.to_vec())
            .with(manifest_url, 200, index.as_bytes().to_vec())
            .with(amd64_url, 200, amd64_manifest.as_bytes().to_vec())
            .with(amd64_blob, 200, amd64_layer)
            .with(arm_blob, 200, arm_layer);

        let files = pull_image(&http, "alpine").expect("pull");
        assert_eq!(
            files.files.get("app/arch.txt").map(Vec::as_slice),
            Some(&b"amd64"[..]),
            "must select the linux/amd64 child manifest"
        );
    }

    #[test]
    fn pull_propagates_manifest_http_failure() {
        let token_url =
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull";
        // Manifest URL is unregistered → mock returns 404 → Err, no panic.
        let http = MockHttpClient::new().with(token_url, 200, br#"{"token":"t"}"#.to_vec());
        assert!(pull_image(&http, "alpine").is_err());
    }

    #[test]
    fn parse_bearer_challenge_full() {
        let c = parse_bearer_challenge(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:o/r:pull""#,
        )
        .unwrap();
        assert_eq!(c.realm, "https://ghcr.io/token");
        assert_eq!(c.service, "ghcr.io");
        assert_eq!(c.scope, "repository:o/r:pull");
    }

    #[test]
    fn parse_bearer_challenge_no_scope_and_bad_scheme() {
        // realm + service, no scope.
        let c = parse_bearer_challenge(r#"Bearer realm="https://x/token",service="x""#).unwrap();
        assert_eq!(c.realm, "https://x/token");
        assert!(c.scope.is_empty());
        // Basic scheme → not a bearer challenge.
        assert!(parse_bearer_challenge(r#"Basic realm="x""#).is_none());
        // No realm → rejected.
        assert!(parse_bearer_challenge("Bearer service=\"x\"").is_none());
    }

    #[test]
    fn base64_encode_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"u:p"), "dTpw");
    }

    #[test]
    fn authenticated_pull_uses_challenge_and_sends_basic_auth() {
        let ping = "https://ghcr.io/v2/";
        let token_url = "https://ghcr.io/token?service=ghcr.io&scope=repository:o/r:pull";
        let manifest_url = "https://ghcr.io/v2/o/r/manifests/1.2";
        let blob = "https://ghcr.io/v2/o/r/blobs/sha256:xxx";

        let layer = gzip(&make_tar(&[("app/f.txt", b"hi")]));
        let manifest = r#"{"schemaVersion":2,"layers":[{"digest":"sha256:xxx"}]}"#;

        let http = MockHttpClient::new()
            .with_headers(
                ping,
                401,
                Vec::new(),
                &[(
                    "WWW-Authenticate",
                    r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:o/r:pull""#,
                )],
            )
            .with(token_url, 200, br#"{"token":"tok"}"#.to_vec())
            .with(manifest_url, 200, manifest.as_bytes().to_vec())
            .with(blob, 200, layer);

        let creds = Credentials {
            username: "u".into(),
            password: "p".into(),
        };
        let files = pull_image_auth(&http, "ghcr.io/o/r:1.2", Some(&creds)).expect("pull");
        assert_eq!(
            files.files.get("app/f.txt").map(Vec::as_slice),
            Some(&b"hi"[..])
        );

        // The token request must carry Basic auth for "u:p" → base64 "dTpw".
        let calls = http.calls.lock().unwrap();
        let sent = http.sent_headers.lock().unwrap();
        let idx = calls
            .iter()
            .position(|(_, url, _)| url == token_url)
            .expect("token call made");
        assert!(
            sent[idx]
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Basic dTpw"),
            "token request should send Basic auth, got {:?}",
            sent[idx]
        );
    }

    #[test]
    fn public_ping_ok_pulls_anonymously() {
        // A 2xx /v2/ ping → no token fetched; manifest served without auth.
        let ping = "https://ghcr.io/v2/";
        let manifest_url = "https://ghcr.io/v2/o/r/manifests/1.2";
        let blob = "https://ghcr.io/v2/o/r/blobs/sha256:yyy";
        let layer = gzip(&make_tar(&[("app/g.txt", b"pub")]));
        let manifest = r#"{"schemaVersion":2,"layers":[{"digest":"sha256:yyy"}]}"#;

        let http = MockHttpClient::new()
            .with(ping, 200, Vec::new())
            .with(manifest_url, 200, manifest.as_bytes().to_vec())
            .with(blob, 200, layer);

        let files = pull_image(&http, "ghcr.io/o/r:1.2").expect("pull");
        assert_eq!(
            files.files.get("app/g.txt").map(Vec::as_slice),
            Some(&b"pub"[..])
        );
        // No token endpoint was contacted.
        let calls = http.calls.lock().unwrap();
        assert!(calls.iter().all(|(_, url, _)| !url.contains("/token")));
    }
}
