//! Run observability: per-package events emitted by scan runners, persisted
//! as an NDJSON run log (`~/.aegis/runs/<run_id>.ndjson`) and optionally
//! rendered live in a terminal dashboard (`--dash`).
//!
//! Deliberately separate from the Go-compatible audit log in `aegis-cli` —
//! this format is ours to evolve (versioned via `v` on `run_started`).

pub mod bus;
pub mod event;
pub mod log;
pub mod state;
pub mod tui;

pub use bus::EventBus;
pub use event::{Event, RunKind};

/// Milliseconds since the unix epoch. Producers stamp events with this so
/// replay can pace by recorded time.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
