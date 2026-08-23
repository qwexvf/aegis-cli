//! Layer overlay — merges every layer's tar into one root filesystem.
//!
//! Mirrors the overlay semantics of the Go scanner (`overlayLayersFull`):
//! layers apply base → top, later layers override earlier, and whiteouts are
//! honoured so the merged map reflects what a `docker run` would actually
//! see:
//!
//!   - `.wh.<name>`  — removes `<dir>/<name>` (file-level whiteout).
//!   - `.wh..wh..opq` — opaque: clears everything under `<dir>/` captured so
//!     far, then this layer's own files under that dir are re-added.
//!
//! Unlike the Go scanner (which only captures registered lockfile paths to
//! bound memory), this first slice captures **every regular file** into the
//! merged map — that's the "flattened root filesystem" the scan step walks.
//! Each file is capped at [`MAX_FILE_BYTES`] to keep a crafted image from
//! exhausting memory.

use std::collections::BTreeMap;
use std::io::Read;

use crate::layout::clean_path;

/// Per-file capture cap. Large enough for any manifest/script we care about;
/// bigger blobs (media, minified bundles) are truncated rather than dropped
/// so a path is still visible to the scan.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Total captured bytes across one layer, and total entries walked. Per-file
/// caps alone don't bound a gzip/tar bomb: a small blob can inflate to millions
/// of tiny entries, each a `Vec` in the merged view — unbounded memory. These
/// stop the walk once a layer looks hostile; a partial view is safe (a bomb is
/// malicious anyway, and legit images sit far under both).
const MAX_LAYER_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_LAYER_ENTRIES: usize = 200_000;

/// The flattened root filesystem of an image after overlaying every layer.
#[derive(Debug, Default, Clone)]
pub struct ImageFiles {
    /// Path (cleaned, no leading `/`) → file bytes. Sorted for deterministic
    /// iteration downstream.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Walk each layer blob in order and produce the merged file map.
pub fn overlay_layers(layers: &[&[u8]]) -> Result<ImageFiles, String> {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (i, blob) in layers.iter().enumerate() {
        let view = read_layer(blob).map_err(|e| format!("image: layer {i}: {e}"))?;
        merge_view(view, &mut files);
    }
    Ok(ImageFiles { files })
}

/// One layer read in isolation: regular files plus the whiteout markers found
/// in it. The merge step applies these against the running overlay.
struct LayerView {
    files: Vec<(String, Vec<u8>)>,
    whiteouts: Vec<String>,
    opaque_dirs: Vec<String>,
}

/// Decompress (gzip-aware) + tar-walk a single layer blob into a [`LayerView`].
fn read_layer(blob: &[u8]) -> Result<LayerView, String> {
    let mut view = LayerView {
        files: Vec::new(),
        whiteouts: Vec::new(),
        opaque_dirs: Vec::new(),
    };
    // Docker save layers are usually plain `layer.tar`; OCI ones are gzipped.
    // Detect the gzip magic and pick the reader accordingly.
    let is_gzip = blob.len() >= 2 && blob[0] == 0x1f && blob[1] == 0x8b;
    if is_gzip {
        let decoder = flate2::read::GzDecoder::new(blob);
        walk_layer_tar(decoder, &mut view)?;
    } else {
        walk_layer_tar(blob, &mut view)?;
    }
    Ok(view)
}

fn walk_layer_tar<R: Read>(reader: R, view: &mut LayerView) -> Result<(), String> {
    let mut archive = tar::Archive::new(reader);
    let iter = archive
        .entries()
        .map_err(|e| format!("read layer tar: {e}"))?;
    let mut total_bytes: u64 = 0;
    let mut entry_count: usize = 0;
    for entry in iter {
        // Bomb guard: stop walking once a layer exceeds the entry or byte
        // budget, keeping the partial view already captured.
        entry_count += 1;
        if entry_count > MAX_LAYER_ENTRIES || total_bytes > MAX_LAYER_TOTAL_BYTES {
            break;
        }
        let mut entry = entry.map_err(|e| format!("layer tar entry: {e}"))?;
        let is_regular = entry.header().entry_type().is_file();
        let raw = entry
            .path()
            .map_err(|e| format!("layer tar entry path: {e}"))?
            .to_string_lossy()
            .into_owned();
        let name = clean_path(&raw);
        if name.is_empty() {
            continue;
        }
        let (dir, base) = split_dir_base(&name);

        if base == ".wh..wh..opq" {
            // Opaque marker for `dir`. Empty dir == image root.
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            view.opaque_dirs.push(prefix);
            continue;
        }
        if let Some(rest) = base.strip_prefix(".wh.") {
            let target = if dir.is_empty() {
                rest.to_string()
            } else {
                format!("{dir}/{rest}")
            };
            view.whiteouts.push(target);
            continue;
        }
        if !is_regular {
            continue;
        }
        let mut buf = Vec::new();
        entry
            .by_ref()
            .take(MAX_FILE_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| format!("read layer file {name}: {e}"))?;
        total_bytes = total_bytes.saturating_add(buf.len() as u64);
        view.files.push((name, buf));
    }
    Ok(())
}

/// Apply one layer's view onto the running overlay. Opaque whiteouts first,
/// then file whiteouts, then this layer's regular files (so a file re-added
/// in the same layer that opaques its dir survives).
fn merge_view(view: LayerView, files: &mut BTreeMap<String, Vec<u8>>) {
    for prefix in &view.opaque_dirs {
        if prefix.is_empty() {
            files.clear();
        } else {
            files.retain(|k, _| !k.starts_with(prefix.as_str()));
        }
    }
    for target in &view.whiteouts {
        files.remove(target);
    }
    for (name, body) in view.files {
        files.insert(name, body);
    }
}

/// Split a cleaned path into `(dir, base)`. `"a/b/c" -> ("a/b", "c")`,
/// `"c" -> ("", "c")`.
fn split_dir_base(name: &str) -> (&str, &str) {
    match name.rsplit_once('/') {
        Some((dir, base)) => (dir, base),
        None => ("", name),
    }
}
