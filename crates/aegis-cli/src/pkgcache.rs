//! On-disk cache of per-package gate verdicts.
//!
//! Not an optimization — the gate is unusable without it. A cold check of a
//! 922-dependency lockfile takes minutes, because each package means a
//! tarball fetch plus an AST scan, and the gate runs in front of an
//! interactive command.
//!
//! What is cached is the **verdict**, not the tarball: a few hundred bytes
//! versus megabytes, with no correctness difference, because both are
//! immutable for a given `(ecosystem, name, exact version)`.
//!
//! Advisories are deliberately *not* folded in here. A published version's
//! code never changes, but the advisories against it do — a CVE can land
//! tomorrow. Those keep their own 7-day OSV cache in `enrich`.

use std::time::Duration;

use aegis_domain::VerdictKind;
use aegis_net::DiskCache;

/// Bumped whenever scoring, capabilities, or the builtin allowlist change, so
/// stale verdicts from an older engine are never served.
///
/// Deliberately not the crate version: keying on that would cold-start every
/// user's cache on every release, including docs-only ones.
const SCAN_SCHEMA: u32 = 1;

/// Capability scans are immutable for an exact version, so this can be long.
const TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

fn cache() -> DiskCache {
    DiskCache::new(crate::enrich::cache_base().join("gate"), Some(TTL))
}

fn key(eco: &str, name: &str, version: &str) -> String {
    format!("{eco}/{name}@{version}#v{SCAN_SCHEMA}")
}

/// A previously computed capability verdict, if we still trust it.
pub(crate) fn get(eco: &str, name: &str, version: &str) -> Option<VerdictKind> {
    let raw = cache().get(&key(eco, name, version))?;
    VerdictKind::parse(std::str::from_utf8(&raw).ok()?.trim())
}

/// Remember a capability verdict. Best-effort: a cache we cannot write is not
/// a reason to fail an install.
pub(crate) fn put(eco: &str, name: &str, version: &str, v: VerdictKind) {
    let _ = cache().put(&key(eco, name, version), v.name().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Point the cache at a scratch dir; `cache_base` honours XDG_CACHE_HOME.
    fn with_tmp_cache<T>(f: impl FnOnce() -> T) -> T {
        // Serialized because the env var is process-global.
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = std::env::temp_dir().join(format!("aegis-pkgcache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var_os("XDG_CACHE_HOME");
        // SAFETY: guarded by LOCK, and the value is restored below.
        unsafe { std::env::set_var("XDG_CACHE_HOME", &dir) };
        let out = f();
        unsafe {
            match prev {
                Some(p) => std::env::set_var("XDG_CACHE_HOME", p),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
        }
        std::fs::remove_dir_all(&dir).ok();
        out
    }

    #[test]
    fn a_stored_verdict_round_trips() {
        with_tmp_cache(|| {
            assert_eq!(get("npm", "lodash", "4.17.21"), None);
            put("npm", "lodash", "4.17.21", VerdictKind::Review);
            assert_eq!(get("npm", "lodash", "4.17.21"), Some(VerdictKind::Review));
            // A different version is a different entry.
            assert_eq!(get("npm", "lodash", "4.17.20"), None);
            // So is a different ecosystem.
            assert_eq!(get("pypi", "lodash", "4.17.21"), None);
        });
    }

    #[test]
    fn the_schema_tag_is_part_of_the_key() {
        // A verdict from an older engine must not be served after a scoring
        // change, which is what bumping SCAN_SCHEMA expresses.
        let a = key("npm", "x", "1.0.0");
        assert!(a.ends_with(&format!("#v{SCAN_SCHEMA}")));
        assert_ne!(a, "npm/x@1.0.0");
    }
}
