//! Event fan-in: producers (rayon workers, xtask loops) send events over an
//! mpsc channel; a collector thread appends every event to the NDJSON run
//! log and, when the dashboard is live, folds it into the shared
//! [`DashState`](crate::state::DashState).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::event::{Event, RunKind, SCHEMA_VERSION};
use crate::log::RunLogWriter;
use crate::state::DashState;

/// Cheap, shareable emit handle. `EventBus::disabled()` is a no-op sink so
/// call sites don't need `if let` everywhere.
#[derive(Clone)]
pub struct EventBus {
    tx: Option<Sender<Event>>,
}

impl EventBus {
    pub fn disabled() -> EventBus {
        EventBus { tx: None }
    }

    pub fn emit(&self, event: Event) {
        if let Some(tx) = &self.tx {
            // collector gone (e.g. run finishing) — nothing useful to do
            let _ = tx.send(event);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }
}

/// Owns the collector thread. Call [`Collector::finish`] after the run's
/// final event to flush and join.
pub struct Collector {
    bus: EventBus,
    handle: JoinHandle<()>,
    /// Path of the NDJSON log being written, for the end-of-run hint.
    pub log_path: Option<PathBuf>,
}

/// Start a run: build the run_id, write `run_started`, spawn the collector.
/// `state` is Some when a live TUI will render this run.
///
/// If the run log can't be created (no HOME, read-only fs) the run proceeds
/// with a warning — observability must never fail the scan.
pub fn start_run(
    kind: RunKind,
    total: usize,
    workers: usize,
    meta: BTreeMap<String, String>,
    state: Option<Arc<Mutex<DashState>>>,
) -> Collector {
    let run_id = format!("{}-{}", kind.as_str(), run_stamp());
    let mut writer = match RunLogWriter::create(&run_id) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("aegis: run log disabled: {e}");
            None
        }
    };
    let log_path = writer.as_ref().map(|w| w.path.clone());

    let (tx, rx) = mpsc::channel::<Event>();
    let bus = EventBus { tx: Some(tx) };
    bus.emit(Event::RunStarted {
        v: SCHEMA_VERSION,
        ts_ms: crate::now_ms(),
        run_id,
        kind,
        total,
        workers,
        meta,
    });

    let handle = std::thread::spawn(move || {
        for event in rx {
            if let Some(w) = writer.as_mut() {
                if let Err(e) = w.append(&event) {
                    eprintln!("aegis: run log write failed, disabling: {e}");
                    writer = None;
                }
            }
            if let Some(s) = &state {
                if let Ok(mut s) = s.lock() {
                    s.apply(&event);
                }
            }
        }
    });

    Collector {
        bus,
        handle,
        log_path,
    }
}

impl Collector {
    pub fn bus(&self) -> EventBus {
        self.bus.clone()
    }

    /// Emit `run_finished`, then drain and join the collector.
    pub fn finish(self, duration_ms: u64, passed: usize, failed: usize, hits: u32, misses: u32) {
        self.bus.emit(Event::RunFinished {
            ts_ms: crate::now_ms(),
            duration_ms,
            passed,
            failed,
            cache_hits: hits,
            cache_misses: misses,
        });
        drop(self.bus); // close the channel so the collector's loop ends
        let _ = self.handle.join();
    }
}

/// `YYYYMMDD-HHMMSS` in UTC, no external time crate needed here — derived
/// from unix seconds with a civil-date conversion (days algorithm from
/// Howard Hinnant's date paper).
fn run_stamp() -> String {
    let secs = crate::now_ms() / 1000;
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    let rem = secs % 86_400;
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn disabled_bus_is_noop() {
        let bus = EventBus::disabled();
        assert!(!bus.is_enabled());
        bus.emit(Event::RunFinished {
            ts_ms: 0,
            duration_ms: 0,
            passed: 0,
            failed: 0,
            cache_hits: 0,
            cache_misses: 0,
        });
    }
}
