//! Image-tarball layout parsing.
//!
//! Turns the outer tarball into an ordered list of layer blobs. Supports two
//! layouts:
//!
//!   - **Docker save**: a root `manifest.json` (`[{ "Layers": [...] }]`)
//!     whose `Layers` entries are paths into the tar (`<id>/layer.tar` for
//!     legacy saves, `blobs/sha256/<hex>` for OCI-flavoured ones).
//!   - **OCI layout**: `index.json` → a manifest blob → its `layers[]`
//!     digests, each mapped to `blobs/sha256/<hex>` inside the tar.
//!
//! Both are informed by the Go scanner's use of go-containerregistry's
//! `tarball.ImageFromPath`; here we resolve the layer list ourselves.

use std::collections::BTreeMap;
use std::io::Read;

use serde::Deserialize;

/// Cap on any single entry read out of the outer tarball. Guards against a
/// crafted archive with an absurd declared size. Layers can legitimately be
/// large; 2 GiB is well past anything realistic for a first slice.
const MAX_ENTRY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
struct DockerManifestEntry {
    #[serde(rename = "Layers", default)]
    layers: Vec<String>,
}

#[derive(Deserialize)]
struct OciIndex {
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciManifest {
    #[serde(default)]
    layers: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    #[serde(default)]
    digest: String,
    #[serde(rename = "mediaType", default)]
    media_type: String,
}

/// Read every entry of the outer tarball into a path → bytes map. The image
/// tar is uncompressed (Docker save / OCI layout are plain tar), so no gzip
/// handling is needed at this level — individual *layers* may be gzipped and
/// are decompressed later.
pub fn read_outer_tar(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut archive = tar::Archive::new(bytes);
    let mut out = BTreeMap::new();
    let iter = archive
        .entries()
        .map_err(|e| format!("image: read outer tar: {e}"))?;
    for entry in iter {
        let mut entry = entry.map_err(|e| format!("image: outer tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("image: outer tar entry path: {e}"))?;
        let name = clean_path(&path.to_string_lossy());
        if name.is_empty() {
            continue;
        }
        let mut buf = Vec::new();
        entry
            .by_ref()
            .take(MAX_ENTRY_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| format!("image: read outer tar entry {name}: {e}"))?;
        out.insert(name, buf);
    }
    Ok(out)
}

/// Resolve the ordered layer blobs (base → top) from the outer-tar entries.
/// Prefers `manifest.json` (Docker save); falls back to `index.json` (OCI).
pub fn ordered_layer_blobs(entries: &BTreeMap<String, Vec<u8>>) -> Result<Vec<&[u8]>, String> {
    if let Some(manifest) = entries.get("manifest.json") {
        return docker_layers(manifest, entries);
    }
    if let Some(index) = entries.get("index.json") {
        return oci_layers(index, entries);
    }
    Err("image: no manifest.json or index.json in tarball".to_string())
}

fn docker_layers<'a>(
    manifest: &[u8],
    entries: &'a BTreeMap<String, Vec<u8>>,
) -> Result<Vec<&'a [u8]>, String> {
    let parsed: Vec<DockerManifestEntry> =
        serde_json::from_slice(manifest).map_err(|e| format!("image: parse manifest.json: {e}"))?;
    let first = parsed
        .into_iter()
        .next()
        .ok_or_else(|| "image: manifest.json is empty".to_string())?;
    let mut out = Vec::with_capacity(first.layers.len());
    for layer_path in &first.layers {
        let key = clean_path(layer_path);
        let blob = entries
            .get(&key)
            .ok_or_else(|| format!("image: layer blob {key} referenced but not in tarball"))?;
        out.push(blob.as_slice());
    }
    Ok(out)
}

fn oci_layers<'a>(
    index: &[u8],
    entries: &'a BTreeMap<String, Vec<u8>>,
) -> Result<Vec<&'a [u8]>, String> {
    let index: OciIndex =
        serde_json::from_slice(index).map_err(|e| format!("image: parse index.json: {e}"))?;
    // Pick the first image manifest descriptor. A real index can carry a
    // multi-arch list; picking the first is fine for the first slice.
    let manifest_desc = index
        .manifests
        .into_iter()
        .find(|d| d.media_type.is_empty() || d.media_type.contains("manifest"))
        .ok_or_else(|| "image: index.json has no manifest descriptor".to_string())?;
    let manifest_blob = blob_for_digest(&manifest_desc.digest, entries)?;
    let manifest: OciManifest = serde_json::from_slice(manifest_blob)
        .map_err(|e| format!("image: parse oci manifest blob: {e}"))?;
    let mut out = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        out.push(blob_for_digest(&layer.digest, entries)?);
    }
    Ok(out)
}

/// Map an OCI digest (`sha256:<hex>`) to its `blobs/sha256/<hex>` entry.
fn blob_for_digest<'a>(
    digest: &str,
    entries: &'a BTreeMap<String, Vec<u8>>,
) -> Result<&'a [u8], String> {
    let (algo, hex) = digest
        .split_once(':')
        .ok_or_else(|| format!("image: malformed digest {digest:?}"))?;
    let key = format!("blobs/{algo}/{hex}");
    entries
        .get(&key)
        .map(|v| v.as_slice())
        .ok_or_else(|| format!("image: blob {key} referenced but not in tarball"))
}

/// Normalise a tar entry path: forward slashes, drop `.` / leading `/` and
/// resolve `..` segments, no trailing slash. OS-independent (tar always uses
/// `/`), so we work on the string directly rather than [`std::path`].
pub fn clean_path(raw: &str) -> String {
    let normalized = raw.replace('\\', "/");
    let mut segs: Vec<&str> = Vec::new();
    for seg in normalized.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    segs.join("/")
}

#[cfg(test)]
mod tests {
    use super::clean_path;

    #[test]
    fn clean_path_normalises() {
        assert_eq!(clean_path("./app/x.sh"), "app/x.sh");
        assert_eq!(clean_path("/app//x.sh"), "app/x.sh");
        assert_eq!(clean_path("app/../etc/passwd"), "etc/passwd");
        assert_eq!(clean_path("blobs/sha256/abc"), "blobs/sha256/abc");
        assert_eq!(clean_path("/"), "");
    }
}
