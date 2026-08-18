//! Glue between the command handlers and `aegis-obs`: starts the run-log
//! collector (always) and the live TUI (only with `--dash`), and hosts the
//! `aegis dash --replay` subcommand.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use aegis_obs::state::DashState;
use aegis_obs::{bus, EventBus, RunKind};

pub(crate) struct RunObs {
    collector: bus::Collector,
    bus: EventBus,
    tui: Option<JoinHandle<std::io::Result<bool>>>,
    started: Instant,
}

impl RunObs {
    pub(crate) fn start(
        kind: RunKind,
        total: usize,
        workers: usize,
        meta: BTreeMap<String, String>,
        dash: bool,
    ) -> RunObs {
        let state = dash.then(|| Arc::new(Mutex::new(DashState::default())));
        let collector = bus::start_run(kind, total, workers, meta, state.clone());
        let bus = collector.bus();
        let tui = state.map(|s| std::thread::spawn(move || aegis_obs::tui::run_live(s)));
        RunObs {
            collector,
            bus,
            tui,
            started: Instant::now(),
        }
    }

    pub(crate) fn bus(&self) -> EventBus {
        self.bus.clone()
    }

    /// Close the run: emit `run_finished`, wait for the TUI (the user
    /// dismisses the frozen summary with `q`), then print the log path so
    /// the run can be replayed.
    pub(crate) fn finish(self, passed: usize, failed: usize, hits: u32, misses: u32) {
        let duration_ms = self.started.elapsed().as_millis() as u64;
        let log_path = self.collector.log_path.clone();
        self.collector.finish(duration_ms, passed, failed, hits, misses);
        if let Some(t) = self.tui {
            let _ = t.join();
            if let Some(p) = log_path {
                eprintln!("aegis: run log: {} (replay: aegis dash)", p.display());
            }
        }
    }
}

/// `aegis dash --replay <path|latest> [--speed N] [--instant]`
pub(crate) fn run_dash(replay: &str, speed: f64, instant: bool) -> ExitCode {
    let path = match aegis_obs::log::resolve_replay_path(replay) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aegis: no run log ({replay}): {e}");
            return ExitCode::from(2);
        }
    };
    let events: Vec<aegis_obs::Event> = match aegis_obs::log::RunLogReader::open(&path) {
        Ok(r) => r.collect(),
        Err(e) => {
            eprintln!("aegis: cannot read {}: {e}", path.display());
            return ExitCode::from(2);
        }
    };
    if events.is_empty() {
        eprintln!("aegis: {} has no events", path.display());
        return ExitCode::from(2);
    }
    match aegis_obs::tui::run_replay(events, speed, instant) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis: dashboard failed: {e}");
            ExitCode::from(2)
        }
    }
}
