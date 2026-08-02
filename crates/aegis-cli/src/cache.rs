//! `aegis cache list` / `clear` — manage the on-disk advisory caches.
//!
//! Go's `cache` command managed a decision/fingerprint cache the Rust port
//! deliberately does not have (it is stateless by design). What Rust *does*
//! keep on disk is the advisory feed cache: the CISA KEV feed at a 24h TTL
//! and OSV advisory documents at 7d, under `$XDG_CACHE_HOME/aegis`. Those
//! are what this manages.
//!
//! Two reasons to expose it: a stale KEV feed changes verdicts, and an
//! air-gapped or CI user needs to know what is being reused between runs.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use serde::Serialize;

/// The known caches, with the TTL each is written under. Kept in one place
/// so `list` can report staleness rather than just a file count.
const POOLS: &[(&str, Duration)] = &[
    ("kev", Duration::from_secs(24 * 60 * 60)),
    ("osv", Duration::from_secs(7 * 24 * 60 * 60)),
];

/// Base cache directory: `$XDG_CACHE_HOME/aegis`, else `$HOME/.cache/aegis`,
/// else the OS temp dir. Mirrors `enrich::cache_base`.
pub(crate) fn cache_base() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("aegis")
}

#[derive(Serialize)]
struct PoolReport {
    name: &'static str,
    path: String,
    entries: usize,
    bytes: u64,
    /// Entries past their TTL — still on disk, but the next run refetches.
    stale: usize,
    ttl_secs: u64,
}

#[derive(Serialize)]
struct CacheReport {
    base: String,
    pools: Vec<PoolReport>,
    total_bytes: u64,
}

fn scan_pool(name: &'static str, ttl: Duration) -> PoolReport {
    let dir = cache_base().join(name);
    let mut entries = 0usize;
    let mut bytes = 0u64;
    let mut stale = 0usize;
    let now = SystemTime::now();

    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            entries += 1;
            bytes += meta.len();
            let expired = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > ttl);
            if expired {
                stale += 1;
            }
        }
    }
    PoolReport {
        name,
        path: dir.display().to_string(),
        entries,
        bytes,
        stale,
        ttl_secs: ttl.as_secs(),
    }
}

pub(crate) fn run_cache_list(json: bool) -> ExitCode {
    let pools: Vec<PoolReport> = POOLS.iter().map(|(n, ttl)| scan_pool(n, *ttl)).collect();
    let total_bytes = pools.iter().map(|p| p.bytes).sum();

    if json {
        let report = CacheReport {
            base: cache_base().display().to_string(),
            pools,
            total_bytes,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }

    println!("cache: {}", cache_base().display());
    println!(
        "{:<8} {:>8} {:>12} {:>8}  TTL",
        "POOL", "ENTRIES", "SIZE", "STALE"
    );
    for p in &pools {
        println!(
            "{:<8} {:>8} {:>12} {:>8}  {}",
            p.name,
            p.entries,
            human_bytes(p.bytes),
            p.stale,
            human_dur(p.ttl_secs)
        );
    }
    println!("total {}", human_bytes(total_bytes));
    if pools.iter().all(|p| p.entries == 0) {
        println!("(empty — nothing has been cached yet)");
    }
    ExitCode::SUCCESS
}

pub(crate) fn run_cache_clear(pool: Option<&str>) -> ExitCode {
    let selected: Vec<&(&str, Duration)> = match pool {
        Some(want) => {
            let Some(p) = POOLS.iter().find(|(n, _)| *n == want) else {
                let names: Vec<&str> = POOLS.iter().map(|(n, _)| *n).collect();
                eprintln!(
                    "aegis: unknown cache pool '{want}' (known: {})",
                    names.join(", ")
                );
                return ExitCode::from(2);
            };
            vec![p]
        }
        None => POOLS.iter().collect(),
    };

    let mut removed = 0usize;
    let mut freed = 0u64;
    for (name, _) in selected {
        let dir = cache_base().join(name);
        match clear_dir(&dir) {
            Ok((n, b)) => {
                removed += n;
                freed += b;
            }
            Err(e) => {
                eprintln!("aegis: cannot clear {}: {e}", dir.display());
                return ExitCode::from(2);
            }
        }
    }
    println!("cleared {removed} entries ({})", human_bytes(freed));
    ExitCode::SUCCESS
}

/// Remove the files in a cache pool, leaving the directory itself. Only
/// touches regular files — never recurses, so a stray directory under the
/// cache is left alone rather than being deleted by surprise.
fn clear_dir(dir: &Path) -> std::io::Result<(usize, u64)> {
    let mut n = 0usize;
    let mut bytes = 0u64;
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e),
    };
    for e in rd.flatten() {
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        std::fs::remove_file(e.path())?;
        n += 1;
        bytes += meta.len();
    }
    Ok((n, bytes))
}

fn human_bytes(b: u64) -> String {
    const K: u64 = 1024;
    match b {
        0 => "0".into(),
        b if b < K => format!("{b} B"),
        b if b < K * K => format!("{:.1} KiB", b as f64 / K as f64),
        b => format!("{:.1} MiB", b as f64 / (K * K) as f64),
    }
}

fn human_dur(secs: u64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s => format!("{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(0), "0");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn human_dur_picks_the_natural_unit() {
        assert_eq!(human_dur(24 * 3600), "1d");
        assert_eq!(human_dur(3600), "1h");
        assert_eq!(human_dur(90), "90s");
    }

    #[test]
    fn clear_dir_is_ok_when_absent() {
        let missing = std::env::temp_dir().join("aegis-cache-does-not-exist-xyz");
        assert_eq!(clear_dir(&missing).unwrap(), (0, 0));
    }

    #[test]
    fn clear_dir_removes_files_but_not_subdirectories() {
        let d = std::env::temp_dir().join(format!("aegis-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("keep")).unwrap();
        std::fs::write(d.join("a"), b"12345").unwrap();
        std::fs::write(d.join("b"), b"123").unwrap();

        let (n, bytes) = clear_dir(&d).unwrap();
        assert_eq!((n, bytes), (2, 8));
        assert!(d.join("keep").is_dir(), "subdirectory must survive");
        assert!(!d.join("a").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_base_follows_xdg() {
        // Sanity: the path ends in `aegis` whichever branch is taken.
        assert!(cache_base().ends_with("aegis"));
    }
}
