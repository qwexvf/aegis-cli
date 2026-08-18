//! Render model for the dashboard: a fold over the event stream. Kept pure
//! (events in, plain data out) so it can be unit-tested and reused by both
//! live mode and replay.

use std::collections::BTreeMap;

use crate::event::{Event, RunKind};

/// What one worker slot is doing right now.
#[derive(Clone, Debug, Default)]
pub struct WorkerSlot {
    /// `Some((pkg@version, started ts_ms))` while busy.
    pub current: Option<(String, u64)>,
    pub done: usize,
}

/// One finished package, kept for the event log pane and slowest-N list.
#[derive(Clone, Debug)]
pub struct FinishedPkg {
    pub ts_ms: u64,
    pub label: String, // eco/pkg@version
    pub duration_ms: u64,
    pub verdict: String,
    pub score: f64,
    pub passed: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DashState {
    pub run_id: String,
    pub kind: Option<RunKind>,
    pub meta: BTreeMap<String, String>,
    pub total: usize,
    pub started_ts_ms: u64,
    pub finished: Vec<FinishedPkg>,
    pub workers: Vec<WorkerSlot>,
    pub passed: usize,
    pub failed: usize,
    pub cache_hits: u32,
    pub cache_misses: u32,
    pub run_over: bool,
    pub run_duration_ms: u64,
    /// last event timestamp seen — replay uses it as "now"
    pub last_ts_ms: u64,
}

impl DashState {
    pub fn apply(&mut self, event: &Event) {
        self.last_ts_ms = self.last_ts_ms.max(event.ts_ms());
        match event {
            Event::RunStarted {
                ts_ms,
                run_id,
                kind,
                total,
                workers,
                meta,
                ..
            } => {
                self.run_id = run_id.clone();
                self.kind = Some(*kind);
                self.total = *total;
                self.meta = meta.clone();
                self.started_ts_ms = *ts_ms;
                self.workers = vec![WorkerSlot::default(); (*workers).max(1)];
            }
            Event::PackageStarted {
                ts_ms,
                worker,
                pkg,
                version,
                ..
            } => {
                let slot = self.slot(*worker);
                slot.current = Some((format!("{pkg}@{version}"), *ts_ms));
            }
            Event::PackageFinished {
                ts_ms,
                worker,
                pkg,
                version,
                eco,
                duration_ms,
                verdict,
                score,
                passed,
                cache_hits,
                cache_misses,
                detail,
                ..
            } => {
                let slot = self.slot(*worker);
                slot.current = None;
                slot.done += 1;
                if *passed {
                    self.passed += 1;
                } else {
                    self.failed += 1;
                }
                self.cache_hits += cache_hits;
                self.cache_misses += cache_misses;
                self.finished.push(FinishedPkg {
                    ts_ms: *ts_ms,
                    label: format!("{eco}/{pkg}@{version}"),
                    duration_ms: *duration_ms,
                    verdict: verdict.clone(),
                    score: *score,
                    passed: *passed,
                    detail: detail.clone(),
                });
            }
            Event::RunFinished {
                duration_ms,
                cache_hits,
                cache_misses,
                ..
            } => {
                self.run_over = true;
                self.run_duration_ms = *duration_ms;
                // run-level cache totals supersede per-package sums when present
                if *cache_hits > 0 || *cache_misses > 0 {
                    self.cache_hits = *cache_hits;
                    self.cache_misses = *cache_misses;
                }
            }
        }
    }

    fn slot(&mut self, worker: usize) -> &mut WorkerSlot {
        if worker >= self.workers.len() {
            self.workers.resize(worker + 1, WorkerSlot::default());
        }
        &mut self.workers[worker]
    }

    pub fn done(&self) -> usize {
        self.finished.len()
    }

    /// Packages per second over the run so far. `now_ms` is wall-clock in
    /// live mode, `last_ts_ms` in replay.
    pub fn throughput(&self, now_ms: u64) -> f64 {
        let elapsed = now_ms.saturating_sub(self.started_ts_ms) as f64 / 1000.0;
        if elapsed <= 0.0 {
            return 0.0;
        }
        self.finished.len() as f64 / elapsed
    }

    pub fn cache_ratio(&self) -> Option<f64> {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return None;
        }
        Some(self.cache_hits as f64 / total as f64)
    }

    /// (p50, p95) of finished durations in ms.
    pub fn percentiles(&self) -> Option<(u64, u64)> {
        if self.finished.is_empty() {
            return None;
        }
        let mut d: Vec<u64> = self.finished.iter().map(|f| f.duration_ms).collect();
        d.sort_unstable();
        let idx = |p: f64| d[(((d.len() - 1) as f64) * p).round() as usize];
        Some((idx(0.50), idx(0.95)))
    }

    /// N slowest finished packages, slowest first.
    pub fn slowest(&self, n: usize) -> Vec<&FinishedPkg> {
        let mut v: Vec<&FinishedPkg> = self.finished.iter().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.duration_ms));
        v.truncate(n);
        v
    }

    /// Duration histogram over `buckets` equal-width bins, for the bar chart.
    pub fn histogram(&self, buckets: usize) -> Vec<(String, u64)> {
        if self.finished.is_empty() || buckets == 0 {
            return Vec::new();
        }
        let max = self
            .finished
            .iter()
            .map(|f| f.duration_ms)
            .max()
            .unwrap_or(0)
            .max(1);
        let width = max.div_ceil(buckets as u64).max(1);
        let mut bins = vec![0u64; buckets];
        for f in &self.finished {
            let i = ((f.duration_ms / width) as usize).min(buckets - 1);
            bins[i] += 1;
        }
        bins.iter()
            .enumerate()
            .map(|(i, &count)| (format_ms(width * (i as u64 + 1)), count))
            .collect()
    }
}

/// Compact duration for tight columns: `312ms`, `3.2s`, `1m04`.
pub fn format_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{:02}", ms / 60_000, (ms % 60_000) / 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SCHEMA_VERSION;

    fn finished(pkg: &str, worker: usize, duration_ms: u64, passed: bool) -> Event {
        Event::PackageFinished {
            ts_ms: 10,
            worker,
            pkg: pkg.into(),
            version: "1.0.0".into(),
            eco: "npm".into(),
            duration_ms,
            verdict: if passed { "safe" } else { "block" }.into(),
            score: 0.0,
            passed,
            cache_hits: 2,
            cache_misses: 1,
            bytes: 0,
            files: 0,
            detail: None,
        }
    }

    #[test]
    fn aggregates_counts_and_percentiles() {
        let mut s = DashState::default();
        s.apply(&Event::RunStarted {
            v: SCHEMA_VERSION,
            ts_ms: 0,
            run_id: "r".into(),
            kind: RunKind::Ci,
            total: 4,
            workers: 2,
            meta: Default::default(),
        });
        s.apply(&Event::PackageStarted {
            ts_ms: 1,
            worker: 0,
            pkg: "a".into(),
            version: "1".into(),
            eco: "npm".into(),
        });
        assert!(s.workers[0].current.is_some());
        for (i, (d, ok)) in [(100, true), (200, true), (400, false), (1000, true)]
            .iter()
            .enumerate()
        {
            s.apply(&finished(&format!("p{i}"), i % 2, *d, *ok));
        }
        assert_eq!(s.done(), 4);
        assert_eq!(s.passed, 3);
        assert_eq!(s.failed, 1);
        assert!(s.workers[0].current.is_none());
        assert_eq!(s.cache_hits, 8);
        assert_eq!(s.cache_misses, 4);
        let (p50, p95) = s.percentiles().unwrap();
        assert_eq!(p50, 400); // nearest-rank on even count rounds up
        assert_eq!(p95, 1000);
        assert_eq!(s.slowest(2)[0].duration_ms, 1000);
        assert_eq!(s.throughput(2000), 2.0);
        assert!((s.cache_ratio().unwrap() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn worker_slot_grows_on_demand() {
        let mut s = DashState::default();
        s.apply(&finished("x", 7, 10, true));
        assert_eq!(s.workers.len(), 8);
        assert_eq!(s.workers[7].done, 1);
    }

    #[test]
    fn format_ms_ranges() {
        assert_eq!(format_ms(312), "312ms");
        assert_eq!(format_ms(3200), "3.2s");
        assert_eq!(format_ms(64_000), "1m04");
    }
}
