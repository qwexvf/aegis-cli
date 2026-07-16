//! Anonymous OCI/Docker registry pull — fetch an image by `repo:tag`
//! reference instead of from a local tarball.
//!
//! Bounded first slice: **unauthenticated pull from a public registry only**.
//! It walks the standard OCI distribution flow — parse the reference, fetch the
//! manifest (following a multi-arch index to its linux/amd64 child), then fetch
//! every layer blob — and feeds the ordered gzipped layer blobs into the exact
//! same [`crate::overlay::overlay_layers`] assembly the tarball path uses, so
//! whiteouts and later-layer-wins semantics are identical.
//!
//! ## Auth
//!
//! [`aegis_net::HttpResponse`] drops response headers, so we can't read a
//! `Www-Authenticate` challenge off a 401. We therefore special-case by host:
//!   - **docker.io** (`registry-1.docker.io`): fetch an anonymous bearer token
//!     from `auth.docker.io` proactively and send it on every request.
//!   - **other registries** (e.g. `ghcr.io`): try anonymously, no token. Public
//!     images there serve manifests/blobs without a bearer for a pull scope.
//!
//! Authenticated pulls (private images, other registries needing a token) are a
//! follow-up. Any HTTP/parse failure returns `Err(String)` — never panics.

use serde::Deserialize;

use aegis_net::HttpClient;

use crate::overlay::{overlay_layers, ImageFiles};

/// Default registry for a bare reference (`alpine`, `library/nginx`).
const DEFAULT_REGISTRY: &str = "registry-1.docker.io";
/// Docker Hub's token-issuing service.
const DOCKER_AUTH_URL: &str =
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:";
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

/// Pull an image by reference and return its flattened root filesystem.
///
/// Anonymous pull only. Feeds the ordered layer blobs into the shared overlay
/// assembly (identical whiteout / later-layer-wins semantics to the tarball
/// path). Best-effort: any HTTP or parse failure returns `Err(String)`.
pub fn pull_image(http: &dyn HttpClient, reference: &str) -> Result<ImageFiles, String> {
    let r = parse_reference(reference)?;

    // docker.io needs a bearer proactively (we can't read Www-Authenticate);
    // other registries are tried anonymously.
    let token = if r.registry == DEFAULT_REGISTRY {
        Some(fetch_docker_token(http, &r.name)?)
    } else {
        None
    };

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

/// Fetch an anonymous pull token from Docker Hub for `name`.
fn fetch_docker_token(http: &dyn HttpClient, name: &str) -> Result<String, String> {
    let url = format!("{DOCKER_AUTH_URL}{name}:pull");
    let resp = http
        .get(&url, &[])
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
}
