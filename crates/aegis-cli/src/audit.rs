//! The local audit log — an append-only record of what was scanned and
//! what the verdict was.
//!
//! Ported from Go's `internal/infra/ndjsonaudit`. NDJSON, one entry per
//! line, at `$AEGIS_AUDIT_DIR/audit.jsonl` (default `~/.aegis/audit.jsonl`).
//!
//! Why it exists: a scanner that blocks something and leaves no trace is
//! hard to operate. "Why did CI fail last Tuesday" and "what did we
//! suppress and when" both need a record that outlives the terminal
//! scrollback.
//!
//! **Concurrency.** Go takes an exclusive `flock` around the append. This
//! port relies on `O_APPEND` plus a single `write` call instead. On Linux
//! that is atomic for a regular file: `O_APPEND` makes the seek-and-write
//! indivisible, and one `write` of a short line is not split. That is
//! enough for the only contention that occurs here — several `aegis`
//! processes appending short lines — and avoids a locking dependency.
//! A reader tolerates a torn line regardless: `tail` skips anything that
//! does not parse rather than failing.
//!
//! **Failure is never fatal.** A scan whose audit write fails still
//! reports its verdict. Losing a log line must not turn a clean scan into
//! an error.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

/// One decision. Field names match Go's `entryDTO` so the two write a
/// compatible log — a directory written by either is readable by both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub ts: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ecosystem: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub package: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The verdict: safe / review / prompt / block.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub decision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub severity: String,
    /// What produced it: `ci`, `analyze`, `aur`, …
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub advisory_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub aegis_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project_dir: String,
}

impl Entry {
    pub(crate) fn new(action: &str) -> Entry {
        Entry {
            ts: now_rfc3339(),
            ecosystem: String::new(),
            package: String::new(),
            version: String::new(),
            decision: String::new(),
            severity: String::new(),
            action: action.into(),
            source: String::new(),
            advisory_id: String::new(),
            aegis_version: env!("CARGO_PKG_VERSION").into(),
            project_dir: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        }
    }
}

/// RFC3339 at second precision. Nanoseconds would push the column past
/// the table width for no operational benefit — the log is read by humans
/// asking "what happened Tuesday", not for ordering sub-millisecond events.
fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub(crate) fn log_path() -> PathBuf {
    std::env::var_os("AEGIS_AUDIT_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".aegis")))
        .unwrap_or_else(std::env::temp_dir)
        .join("audit.jsonl")
}

/// Append one entry. Errors are swallowed by design — see the module note.
pub(crate) fn write(entry: &Entry) {
    let _ = try_write(entry);
}

fn try_write(entry: &Entry) -> std::io::Result<()> {
    let path = log_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut line = serde_json::to_string(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    let mut f = open_append(&path)?;
    // One write call, deliberately — see the module note on atomicity.
    f.write_all(line.as_bytes())
}

fn open_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The log records what a machine scanned and when; other users
        // have no business reading it.
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Read the last `n` entries, oldest first. `n <= 0` returns everything.
///
/// A line that does not parse is skipped rather than fatal: one torn
/// append must not make the whole log unreadable.
pub(crate) fn tail(n: usize) -> std::io::Result<Vec<Entry>> {
    let path = log_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let all: Vec<Entry> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if n == 0 || n >= all.len() {
        return Ok(all);
    }
    Ok(all[all.len() - n..].to_vec())
}

pub(crate) fn run_audit_tail(n: usize, json: bool) -> ExitCode {
    let entries = match tail(n) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("aegis: {}: {e}", log_path().display());
            return ExitCode::from(2);
        }
    };
    if json {
        match serde_json::to_string_pretty(&entries) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }
    if entries.is_empty() {
        println!("audit log is empty ({})", log_path().display());
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<22} {:<9} {:<8} {:<30} {:<12} DECISION",
        "TIMESTAMP", "ACTION", "ECO", "PACKAGE", "VERSION"
    );
    for e in &entries {
        println!(
            "{:<22} {:<9} {:<8} {:<30} {:<12} {}",
            e.ts,
            e.action,
            e.ecosystem,
            trunc(&e.package, 30),
            trunc(&e.version, 12),
            e.decision
        );
    }
    println!("{} entries — {}", entries.len(), log_path().display());
    ExitCode::SUCCESS
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Point AEGIS_AUDIT_DIR at a scratch dir for the duration of a test.
    /// Tests that use this must not run concurrently with each other, so
    /// they are collapsed into one test function.
    fn with_temp_log<T>(f: impl FnOnce() -> T) -> T {
        let d = std::env::temp_dir().join(format!(
            "aegis-audit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::env::set_var("AEGIS_AUDIT_DIR", &d);
        let out = f();
        std::env::remove_var("AEGIS_AUDIT_DIR");
        let _ = std::fs::remove_dir_all(&d);
        out
    }

    #[test]
    fn write_then_tail_roundtrips_and_degrades_gracefully() {
        with_temp_log(|| {
            assert!(tail(0).unwrap().is_empty(), "absent log reads as empty");

            for i in 0..5 {
                let mut e = Entry::new("ci");
                e.package = format!("pkg{i}");
                e.ecosystem = "npm".into();
                e.decision = "safe".into();
                write(&e);
            }

            let all = tail(0).unwrap();
            assert_eq!(all.len(), 5);
            assert_eq!(all[0].package, "pkg0", "oldest first");
            assert_eq!(all[4].package, "pkg4");

            let last2 = tail(2).unwrap();
            assert_eq!(last2.len(), 2);
            assert_eq!(last2[0].package, "pkg3");

            // n larger than the log returns everything.
            assert_eq!(tail(99).unwrap().len(), 5);

            // A torn line must not break the reader.
            let p = log_path();
            let mut raw = std::fs::read_to_string(&p).unwrap();
            raw.push_str("{\"ts\": truncated-garbage\n");
            std::fs::write(&p, raw).unwrap();
            assert_eq!(tail(0).unwrap().len(), 5, "bad line skipped, rest intact");
        });
    }

    #[test]
    fn entry_stamps_version_and_timestamp() {
        let e = Entry::new("analyze");
        assert_eq!(e.action, "analyze");
        assert_eq!(e.aegis_version, env!("CARGO_PKG_VERSION"));
        // RFC3339, so it sorts lexically and parses.
        assert!(e.ts.contains('T'), "{}", e.ts);
        assert!(e.ts.ends_with('Z'), "{}", e.ts);
    }

    #[test]
    fn empty_fields_are_omitted_from_the_json() {
        // Keeps the log compatible with Go's reader, which treats absent
        // and empty the same but should not see nulls.
        let e = Entry::new("ci");
        let s = serde_json::to_string(&e).unwrap();
        assert!(!s.contains("\"package\""), "{s}");
        assert!(!s.contains("null"), "{s}");
        assert!(s.contains("\"action\":\"ci\""), "{s}");
    }
}
