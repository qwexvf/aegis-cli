//! OCI / Docker container-image supply-chain scanning.
//!
//! Clean-room Rust port informed by the Go image scanner
//! (`internal/infra/scan/image`). This is a **bounded first slice** — it
//! reads a `docker save` / OCI-layout image tarball from local disk (bytes
//! or a path), overlays every layer into a single merged root filesystem
//! (whiteout-aware, later layers win), and runs a handful of simple,
//! self-contained path/content risk checks over the result.
//!
//! Deliberately out of scope for this slice (follow-ups):
//!   - Registry pull (no auth flow / remote image fetch).
//!   - Deep per-file capability scanning via `aegis-ast` / `aegis-heuristics`
//!     — the scan step here is intentionally shallow and only flags obviously
//!     risky *paths* (droppers in temp dirs, hidden binaries, embedded
//!     package manifests). Wiring the AST/heuristics pipeline per captured
//!     package is the next step.
//!   - OS package databases (apk / dpkg / rpm), per-layer attribution.
//!   - Streaming: the whole outer tarball is read into memory. Fine for the
//!     first slice; a streaming layout reader is a later optimisation.
//!
//! No panics on malformed input: a bad tarball, truncated gzip, or missing
//! manifest returns `Err(String)`, never unwinds.

mod layout;
mod overlay;
mod scan;

pub use overlay::ImageFiles;
pub use scan::{scan_image_files, Finding};

use std::path::Path;

/// Extract the flattened root filesystem from an image tarball on disk.
///
/// `path` is a `docker save` output tar or an OCI-layout tar. Returns the
/// merged file map after applying every layer's overlay + whiteouts in order.
pub fn extract_image_from_path(path: &Path) -> Result<ImageFiles, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("image: read {}: {e}", path.display()))?;
    extract_image_from_bytes(&bytes)
}

/// Extract the flattened root filesystem from image-tarball bytes.
///
/// Parses `manifest.json` (Docker save) or `index.json` + blobs (OCI layout)
/// to find the ordered layer digests, decompresses each layer (gzip-aware),
/// and overlays them into one file map.
pub fn extract_image_from_bytes(bytes: &[u8]) -> Result<ImageFiles, String> {
    let entries = layout::read_outer_tar(bytes)?;
    let layers = layout::ordered_layer_blobs(&entries)?;
    overlay::overlay_layers(&layers)
}

/// Convenience: extract + scan an image tarball at `path` in one call.
pub fn scan_image_path(path: &Path) -> Result<Vec<Finding>, String> {
    let files = extract_image_from_path(path)?;
    Ok(scan_image_files(&files))
}
