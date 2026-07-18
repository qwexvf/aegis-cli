//! `xtask` — repo automation. Currently one command: the golden-output
//! parity harness.
//!
//! ```text
//! cargo run -p xtask -- parity            # diff Rust --json vs goldens
//! cargo run -p xtask -- parity --record   # (re)capture goldens from Rust
//! ```
//!
//! Each case (see `xtask/parity_cases.toml`) names the `aegis` args to run and
//! a golden file. `parity` runs the Rust binary, parses its `--json`, and
//! structurally diffs it against the golden ([`jsondiff`], order-independent).
//!
//! ## Bridging the Go/Rust arg divergence
//!
//! The Go CLI is snapshot/registry-model and the Rust port is lockfile-direct,
//! so the two can't be run with identical args for a live diff. The golden
//! model resolves this: a case's `args` drive the Rust binary, while the
//! golden is captured once from the reference (Go v0.29) with *its* args. The
//! per-case `args`→golden pairing is the schema-mapping layer. Goldens
//! recorded here with `--record` are **Rust-candidate** goldens (a starting
//! baseline / regression guard); true parity means replacing them with
//! Go-captured output — a data task that needs the Go binary, no longer an
//! architectural blocker.

use std::path::Path;
use std::process::Command;

use serde::Deserialize;

mod jsondiff;

#[derive(Deserialize)]
struct Cases {
    case: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    /// `aegis` CLI args (paths relative to the repo root).
    args: Vec<String>,
    /// Golden file path (relative to the repo root).
    golden: String,
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("parity") => {
            let record = args.iter().any(|a| a == "--record");
            run_parity(record)
        }
        _ => {
            eprintln!("usage: xtask parity [--record]");
            std::process::ExitCode::from(2)
        }
    }
}

fn run_parity(record: bool) -> std::process::ExitCode {
    let manifest_path = "xtask/parity_cases.toml";
    let manifest = match std::fs::read_to_string(manifest_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask: cannot read {manifest_path}: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let cases: Cases = match toml::from_str(&manifest) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xtask: parse {manifest_path}: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let mut failures = 0usize;
    for c in &cases.case {
        match run_case(c, record) {
            Ok(msg) => println!("ok    {} — {msg}", c.name),
            Err(msg) => {
                println!("FAIL  {} — {msg}", c.name);
                failures += 1;
            }
        }
    }

    if record {
        println!("\nrecorded {} golden(s)", cases.case.len());
        return std::process::ExitCode::SUCCESS;
    }
    if failures == 0 {
        println!("\nparity: {} case(s) green", cases.case.len());
        std::process::ExitCode::SUCCESS
    } else {
        println!("\nparity: {failures} case(s) FAILED");
        std::process::ExitCode::from(1)
    }
}

/// Run one case's Rust command, capture `--json` stdout, then either record it
/// as the golden (`record`) or structurally diff it against the stored golden.
fn run_case(c: &Case, record: bool) -> Result<String, String> {
    let actual = run_aegis(&c.args)?;
    let actual_json: serde_json::Value =
        serde_json::from_str(&actual).map_err(|e| format!("actual output is not JSON: {e}"))?;

    if record {
        let pretty = serde_json::to_string_pretty(&actual_json).unwrap_or(actual);
        if let Some(parent) = Path::new(&c.golden).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&c.golden, pretty + "\n")
            .map_err(|e| format!("write golden {}: {e}", c.golden))?;
        return Ok(format!("recorded {}", c.golden));
    }

    let golden_str = std::fs::read_to_string(&c.golden)
        .map_err(|e| format!("read golden {} (record first?): {e}", c.golden))?;
    let golden_json: serde_json::Value =
        serde_json::from_str(&golden_str).map_err(|e| format!("golden is not JSON: {e}"))?;

    match jsondiff::diff(&golden_json, &actual_json) {
        None => Ok("structural match".to_string()),
        Some(m) => Err(m),
    }
}

/// Invoke the `aegis` binary via cargo with `args`, returning its stdout.
/// A non-zero exit is fine for commands that signal findings via exit code —
/// we diff stdout regardless, but a build failure (no stdout) errors.
fn run_aegis(args: &[String]) -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);
    cmd.args(["run", "-q", "-p", "aegis-cli", "--"]).args(args);
    let out = cmd
        .output()
        .map_err(|e| format!("spawn aegis {args:?}: {e}"))?;
    if out.stdout.is_empty() {
        return Err(format!(
            "aegis {args:?} produced no stdout (stderr: {})",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("aegis stdout not utf8: {e}"))
}
