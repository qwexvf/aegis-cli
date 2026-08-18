use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What kind of run produced this log.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    /// `aegis run <aegis.toml>` fleet scan.
    Run,
    /// `aegis ci <lockfile>` dependency gate.
    Ci,
    /// `cargo xtask analyze-parity`.
    AnalyzeParity,
    /// `cargo xtask ci-parity`.
    CiParity,
    /// `cargo xtask sbom-parity`.
    SbomParity,
}

impl RunKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunKind::Run => "run",
            RunKind::Ci => "ci",
            RunKind::AnalyzeParity => "analyze-parity",
            RunKind::CiParity => "ci-parity",
            RunKind::SbomParity => "sbom-parity",
        }
    }
}

/// One line of the NDJSON run log. The schema is versioned by the `v` field
/// on `RunStarted`; unknown fields are ignored on read so old readers survive
/// additive changes.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    RunStarted {
        /// schema version
        v: u32,
        ts_ms: u64,
        run_id: String,
        kind: RunKind,
        /// units of work expected (packages / fixtures / deps); 0 = unknown
        total: usize,
        /// parallel worker count (rayon threads; 1 for sequential loops)
        workers: usize,
        /// free-form run context (lockfile path, corpus dir, ...)
        #[serde(default)]
        meta: BTreeMap<String, String>,
    },
    PackageStarted {
        ts_ms: u64,
        worker: usize,
        pkg: String,
        version: String,
        eco: String,
    },
    PackageFinished {
        ts_ms: u64,
        worker: usize,
        pkg: String,
        version: String,
        eco: String,
        duration_ms: u64,
        /// scan verdict (safe/review/prompt/block) or parity "ok"/"fail"
        verdict: String,
        score: f64,
        passed: bool,
        #[serde(default)]
        cache_hits: u32,
        #[serde(default)]
        cache_misses: u32,
        #[serde(default)]
        bytes: u64,
        #[serde(default)]
        files: u32,
        /// parity diff text or error message, when there is one
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    RunFinished {
        ts_ms: u64,
        duration_ms: u64,
        passed: usize,
        failed: usize,
        #[serde(default)]
        cache_hits: u32,
        #[serde(default)]
        cache_misses: u32,
    },
}

pub const SCHEMA_VERSION: u32 = 1;

impl Event {
    pub fn ts_ms(&self) -> u64 {
        match self {
            Event::RunStarted { ts_ms, .. }
            | Event::PackageStarted { ts_ms, .. }
            | Event::PackageFinished { ts_ms, .. }
            | Event::RunFinished { ts_ms, .. } => *ts_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let events = vec![
            Event::RunStarted {
                v: SCHEMA_VERSION,
                ts_ms: 1,
                run_id: "ci-20260806-120000".into(),
                kind: RunKind::Ci,
                total: 2,
                workers: 8,
                meta: BTreeMap::from([("source".to_string(), "package-lock.json".to_string())]),
            },
            Event::PackageStarted {
                ts_ms: 2,
                worker: 0,
                pkg: "lodash".into(),
                version: "4.17.21".into(),
                eco: "npm".into(),
            },
            Event::PackageFinished {
                ts_ms: 5,
                worker: 0,
                pkg: "lodash".into(),
                version: "4.17.21".into(),
                eco: "npm".into(),
                duration_ms: 3,
                verdict: "safe".into(),
                score: 0.0,
                passed: true,
                cache_hits: 4,
                cache_misses: 1,
                bytes: 1024,
                files: 12,
                detail: None,
            },
            Event::RunFinished {
                ts_ms: 6,
                duration_ms: 5,
                passed: 1,
                failed: 0,
                cache_hits: 4,
                cache_misses: 1,
            },
        ];
        for e in events {
            let line = serde_json::to_string(&e).unwrap();
            let back: Event = serde_json::from_str(&line).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                line,
                "round trip changed: {line}"
            );
        }
    }

    #[test]
    fn tag_is_snake_case() {
        let e = Event::PackageStarted {
            ts_ms: 0,
            worker: 0,
            pkg: "x".into(),
            version: "1".into(),
            eco: "npm".into(),
        };
        let line = serde_json::to_string(&e).unwrap();
        assert!(line.contains("\"event\":\"package_started\""), "{line}");
    }
}
