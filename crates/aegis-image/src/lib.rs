//! OCI / Docker container-image supply-chain scanning.
//!
//! Clean-room Rust port informed by the Go image scanner
//! (`internal/infra/scan/image`). This is a **bounded first slice** — it
//! reads a `docker save` / OCI-layout image tarball from local disk (bytes
//! or a path), overlays every layer into a single merged root filesystem
//! (whiteout-aware, later layers win), and runs a handful of simple,
//! self-contained path/content risk checks over the result.
//!
//! Three scan passes are available over the merged filesystem:
//!   - [`scan_image_files`] — the shallow path/content risk checks (droppers
//!     in temp dirs, hidden binaries, embedded package manifests).
//!   - [`deep_scan_image_files`] — runs the project's `aegis-heuristics`
//!     source-pattern detector over each text/code file and surfaces the
//!     capabilities it emits (shell-fetchers, obfuscated payloads, C2 URLs,
//!     malware IOC filenames). Substring matching, not parsing.
//!   - [`ast_scan_image_files`] — feeds each source file to the `aegis-ast`
//!     tree-sitter capability scanner (real AST parsing, grammar-per-language
//!     picked by extension) and maps the emitted capabilities to findings.
//!     Far fewer false positives than the pattern pass on code-shaped strings.
//!
//! Deliberately out of scope for this slice (follow-ups):
//!   - Registry pull (no auth flow / remote image fetch).
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
pub use scan::{ast_scan_image_files, deep_scan_image_files, scan_image_files, Finding};

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
