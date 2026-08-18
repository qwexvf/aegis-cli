//! NDJSON run-log persistence. One `Event` per line, appended as the run
//! progresses. Lives under `$AEGIS_RUNS_DIR` (default `~/.aegis/runs/`);
//! a `latest` pointer file holds the path of the most recent log so
//! `aegis dash --replay latest` works without shell globbing.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::event::Event;

/// Directory run logs live in. Overridable for tests via `AEGIS_RUNS_DIR`.
pub fn runs_dir() -> Option<PathBuf> {
    std::env::var_os("AEGIS_RUNS_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".aegis").join("runs")))
}

/// Append-only writer for one run's NDJSON log.
pub struct RunLogWriter {
    file: File,
    pub path: PathBuf,
}

impl RunLogWriter {
    /// Create `<runs_dir>/<run_id>.ndjson` and update the `latest` pointer.
    pub fn create(run_id: &str) -> std::io::Result<RunLogWriter> {
        let dir = runs_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME / AEGIS_RUNS_DIR")
        })?;
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{run_id}.ndjson"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // pointer file, not a symlink — portable and atomic enough for a dev tool
        let _ = fs::write(dir.join("latest"), path.display().to_string());
        Ok(RunLogWriter { file, path })
    }

    pub fn append(&mut self, event: &Event) -> std::io::Result<()> {
        let line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writeln!(self.file, "{line}")
    }
}

/// Resolve a `--replay` argument: `latest` reads the pointer file, anything
/// else is a path.
pub fn resolve_replay_path(arg: &str) -> std::io::Result<PathBuf> {
    if arg == "latest" {
        let dir = runs_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME / AEGIS_RUNS_DIR")
        })?;
        let p = fs::read_to_string(dir.join("latest"))?;
        Ok(PathBuf::from(p.trim()))
    } else {
        Ok(PathBuf::from(arg))
    }
}

/// Iterator over events in a persisted run log. Malformed lines are skipped
/// (a crashed run may leave a torn last line).
pub struct RunLogReader {
    lines: std::io::Lines<BufReader<File>>,
}

impl RunLogReader {
    pub fn open(path: &Path) -> std::io::Result<RunLogReader> {
        Ok(RunLogReader {
            lines: BufReader::new(File::open(path)?).lines(),
        })
    }
}

impl Iterator for RunLogReader {
    type Item = Event;
    fn next(&mut self) -> Option<Event> {
        for line in self.lines.by_ref() {
            let line = line.ok()?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(e) = serde_json::from_str::<Event>(&line) {
                return Some(e);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{RunKind, SCHEMA_VERSION};

    #[test]
    fn write_then_read_back() {
        let dir = std::env::temp_dir().join(format!("aegis-obs-test-{}", std::process::id()));
        std::env::set_var("AEGIS_RUNS_DIR", &dir);
        let mut w = RunLogWriter::create("test-run").unwrap();
        let start = Event::RunStarted {
            v: SCHEMA_VERSION,
            ts_ms: 1,
            run_id: "test-run".into(),
            kind: RunKind::Ci,
            total: 1,
            workers: 1,
            meta: Default::default(),
        };
        let end = Event::RunFinished {
            ts_ms: 9,
            duration_ms: 8,
            passed: 1,
            failed: 0,
            cache_hits: 0,
            cache_misses: 0,
        };
        w.append(&start).unwrap();
        w.append(&end).unwrap();

        let latest = resolve_replay_path("latest").unwrap();
        assert_eq!(latest, w.path);
        let events: Vec<Event> = RunLogReader::open(&w.path).unwrap().collect();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::RunStarted { .. }));
        assert!(matches!(events[1], Event::RunFinished { .. }));

        std::env::remove_var("AEGIS_RUNS_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reader_skips_torn_lines() {
        let dir = std::env::temp_dir().join(format!("aegis-obs-torn-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("torn.ndjson");
        fs::write(&p, "{\"event\":\"run_finished\",\"ts_ms\":1,\"duration_ms\":1,\"passed\":0,\"failed\":0}\n{\"event\":\"run_fin").unwrap();
        let events: Vec<Event> = RunLogReader::open(&p).unwrap().collect();
        assert_eq!(events.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
