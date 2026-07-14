//! Crash-safe on-disk byte cache. Ports `internal/infra/atomicwrite`
//! (tmp-write → fsync → rename → dir-fsync) + the TTL-by-mtime pattern
//! shared by the OSV advisory cache and the KEV 24h feed cache.
//!
//! This is the reusable building block; the enrich/usecase layer wires
//! it around HTTP calls (as Go's `httpx` does), so the network adapters
//! stay transport-only and testable without touching the filesystem.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A directory-backed cache keyed by arbitrary strings. Entries expire
/// by file mtime when a TTL is set (`None` = never expire).
pub struct DiskCache {
    dir: PathBuf,
    ttl: Option<Duration>,
}

impl DiskCache {
    /// Cache rooted at `dir`. The directory is created lazily on `put`.
    pub fn new(dir: impl Into<PathBuf>, ttl: Option<Duration>) -> Self {
        DiskCache {
            dir: dir.into(),
            ttl,
        }
    }

    /// Load a cached entry, or None on miss / expiry / any read error.
    /// All failure modes degrade to "miss" so the caller re-fetches.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let path = self.path(key);
        let meta = fs::metadata(&path).ok()?;
        if let Some(ttl) = self.ttl {
            let modified = meta.modified().ok()?;
            if SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::ZERO)
                > ttl
            {
                return None; // stale
            }
        }
        fs::read(&path).ok()
    }

    /// Store an entry, creating the cache directory if needed. Best-effort:
    /// a write failure is returned but callers typically ignore it (the
    /// cache is an optimization, not a correctness requirement).
    pub fn put(&self, key: &str, data: &[u8]) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        atomic_write(&self.path(key), data)
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{}.bin", sanitize_key(key)))
    }
}

/// Make a cache key safe as a filename: keep `[A-Za-z0-9._-]`, replace
/// everything else with `_`. Mirrors `sanitizeID`.
fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Durable write: tmp file in the same dir → fsync → rename → fsync dir.
/// On success the destination holds either the full new contents or the
/// previous contents, never a truncated half-write. Mirrors
/// `atomicwrite.WriteFile`.
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("cache");
    // Unique-enough temp name without rand: pid + a process-lifetime counter.
    let tmp = dir.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        next_seq()
    ));

    let write_result = (|| {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir);
    Ok(())
}

/// Monotonic per-process counter for temp-file uniqueness.
fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    // fsync the directory entry so the rename is durable across crashes.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {
    // No portable directory-fsync on Windows; the CLI isn't supported there.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-cache-{}-{}-{}",
            tag,
            std::process::id(),
            next_seq()
        ))
    }

    #[test]
    fn put_then_get_roundtrips() {
        let dir = temp_dir("rt");
        let cache = DiskCache::new(&dir, None);
        cache.put("GHSA-xxxx", b"payload").unwrap();
        assert_eq!(cache.get("GHSA-xxxx").as_deref(), Some(&b"payload"[..]));
        assert!(cache.get("absent").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_ttl_treats_everything_as_stale() {
        let dir = temp_dir("ttl");
        let cache = DiskCache::new(&dir, Some(Duration::ZERO));
        cache.put("k", b"v").unwrap();
        // With a zero TTL any positive age is stale → miss.
        assert!(cache.get("k").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_sanitization_prevents_path_escape() {
        assert_eq!(sanitize_key("../etc/passwd"), ".._etc_passwd");
        assert_eq!(sanitize_key("GHSA-1_2.3"), "GHSA-1_2.3");
        // A traversal-shaped key stays inside the cache dir.
        let dir = temp_dir("esc");
        let cache = DiskCache::new(&dir, None);
        cache.put("../../evil", b"x").unwrap();
        assert!(cache.path("../../evil").starts_with(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
