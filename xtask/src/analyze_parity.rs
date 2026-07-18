//! `xtask analyze-parity [--record]` — the analyze-command parity gate.
//!
//! Walks the vendored incident corpus (`examples/incidents/<eco>/<fixture>/`),
//! runs the Rust `aegis analyze <dir>` on each, and compares its normalized
//! result — `{verdict, score, capabilities}` — against a committed golden
//! (`<fixture>/analyze.golden.json`). Exit non-zero if any fixture diverges.
//!
//! The golden is captured from the reference Go binary (`--record`), so this
//! is a true Go-vs-Rust parity gate; at check time no Go toolchain is needed
//! (goldens are committed), which keeps CI portable. `--record` locates the Go
//! binary via `$AEGIS_GO_BIN`, else builds it from the sibling `../aegis-cli`
//! Go module with `GOWORK=off go build ./cmd/aegis`.
//!
//! The Go/Rust invocation bridge: Go `analyze <eco>/<name>@<ver> --local <dir>`
//! and Rust `analyze <dir> --name <name> --ecosystem <eco>` both AST-scan the
//! same local tree, so their normalized results are directly comparable.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

const INCIDENTS: &str = "examples/incidents";
const GO_REPO: &str = "../aegis-cli";

/// The comparable slice of an analyze result — the fields that define a
/// verdict. Field names accept both the Rust (`score`) and Go (`risk_score`)
/// spellings on the way in.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Norm {
    verdict: String,
    score: i64,
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
struct RawResult {
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    score: Option<i64>,
    #[serde(default)]
    risk_score: Option<i64>,
    #[serde(default)]
    capabilities: Vec<String>,
}

impl Norm {
    fn from_json(s: &str) -> Result<Norm, String> {
        let r: RawResult =
            serde_json::from_str(s).map_err(|e| format!("parse analyze json: {e}"))?;
        let mut caps = r.capabilities;
        caps.sort();
        caps.dedup();
        Ok(Norm {
            verdict: r.verdict,
            score: r.score.or(r.risk_score).unwrap_or(0),
            capabilities: caps,
        })
    }
}

/// One fixture to check: its directory plus the derived (ecosystem, name,
/// version) used to invoke the analyzers.
struct Fixture {
    dir: PathBuf,
    eco: String,
    name: String,
    version: String,
    golden: PathBuf,
}

pub fn run(record: bool) -> std::process::ExitCode {
    let fixtures = match discover() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("xtask: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    if fixtures.is_empty() {
        eprintln!("xtask: no fixtures under {INCIDENTS}");
        return std::process::ExitCode::from(2);
    }

    let go_bin = if record {
        match locate_go_binary() {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("xtask: --record needs the Go binary: {e}");
                return std::process::ExitCode::from(2);
            }
        }
    } else {
        None
    };

    let mut fail = 0usize;
    let mut pass = 0usize;
    let mut cur_eco = String::new();
    for f in &fixtures {
        if f.eco != cur_eco {
            cur_eco = f.eco.clone();
            println!("[{}]", f.eco);
        }
        match check_one(f, go_bin.as_deref(), record) {
            Ok(msg) => {
                pass += 1;
                println!("  ok   {} — {msg}", f.name);
            }
            Err(msg) => {
                fail += 1;
                println!("  FAIL {} — {msg}", f.name);
            }
        }
    }

    if record {
        println!("\nrecorded {pass} golden(s)");
        return std::process::ExitCode::SUCCESS;
    }
    println!("\nanalyze-parity: {pass}/{} match", pass + fail);
    if fail == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

/// Enumerate fixture roots: direct children of each ecosystem dir, descending
/// one level into `@scope` dirs (npm scoped packages).
fn discover() -> Result<Vec<Fixture>, String> {
    let root = Path::new(INCIDENTS);
    if !root.is_dir() {
        return Err(format!("{INCIDENTS} not found (run from the repo root)"));
    }
    let mut out = Vec::new();
    let mut ecos: Vec<_> = std::fs::read_dir(root)
        .map_err(|e| format!("read {INCIDENTS}: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    ecos.sort();
    for eco_dir in ecos {
        let eco = file_name(&eco_dir);
        let mut children: Vec<PathBuf> = read_dirs(&eco_dir)?;
        children.sort();
        for child in children {
            let base = file_name(&child);
            if base.starts_with('@') {
                let mut gcs = read_dirs(&child)?;
                gcs.sort();
                for gc in gcs {
                    out.push(make_fixture(&eco, Some(&base), gc));
                }
            } else {
                out.push(make_fixture(&eco, None, child));
            }
        }
    }
    Ok(out)
}

fn make_fixture(eco: &str, scope: Option<&str>, dir: PathBuf) -> Fixture {
    let base = file_name(&dir);
    let (mut name, version) = split_name_version(&base);
    if let Some(s) = scope {
        name = format!("{s}/{name}");
    }
    let golden = dir.join("analyze.golden.json");
    Fixture {
        eco: eco.to_string(),
        name,
        version,
        golden,
        dir,
    }
}

/// Split `foo-bar-1.2.3` into (`foo-bar`, `1.2.3`): the version is the last
/// `-`-delimited segment that starts with a digit (an optional leading `v`
/// stripped). No such segment → the whole base is the name, version empty.
fn split_name_version(base: &str) -> (String, String) {
    if let Some(idx) = base.rfind('-') {
        let after = &base[idx + 1..];
        let digit_start = after.strip_prefix('v').unwrap_or(after);
        if digit_start
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            return (base[..idx].to_string(), digit_start.to_string());
        }
    }
    (base.to_string(), String::new())
}

fn check_one(f: &Fixture, go_bin: Option<&Path>, record: bool) -> Result<String, String> {
    if record {
        let go = go_bin.ok_or("no Go binary")?;
        let out = run_go_analyze(go, f)?;
        let norm = Norm::from_json(&out)?;
        let json =
            serde_json::to_string_pretty(&norm).map_err(|e| format!("encode golden: {e}"))?;
        std::fs::write(&f.golden, json + "\n")
            .map_err(|e| format!("write {}: {e}", f.golden.display()))?;
        return Ok(format!("recorded (v={}, s={})", norm.verdict, norm.score));
    }

    let rust_out = run_rust_analyze(f)?;
    let rust = Norm::from_json(&rust_out)?;
    let golden_str = std::fs::read_to_string(&f.golden)
        .map_err(|e| format!("read golden {} (record first?): {e}", f.golden.display()))?;
    let golden: Norm =
        serde_json::from_str(&golden_str).map_err(|e| format!("parse golden: {e}"))?;

    if rust == golden {
        Ok(format!("v={}, s={}", rust.verdict, rust.score))
    } else {
        Err(format!(
            "DIVERGED\n       golden: v={}, s={}, caps={:?}\n       rust:   v={}, s={}, caps={:?}",
            golden.verdict,
            golden.score,
            golden.capabilities,
            rust.verdict,
            rust.score,
            rust.capabilities
        ))
    }
}

fn run_rust_analyze(f: &Fixture) -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(["run", "-q", "-p", "aegis-cli", "--", "analyze"])
        .arg(&f.dir)
        .args(["--name", &f.name, "--ecosystem", &f.eco, "--json"])
        .output()
        .map_err(|e| format!("spawn rust analyze: {e}"))?;
    stdout_or_err(out, "rust analyze")
}

fn run_go_analyze(go: &Path, f: &Fixture) -> Result<String, String> {
    let spec = if f.version.is_empty() {
        format!("{}/{}", f.eco, f.name)
    } else {
        format!("{}/{}@{}", f.eco, f.name, f.version)
    };
    let out = Command::new(go)
        .args(["analyze", &spec, "--local"])
        .arg(&f.dir)
        .arg("--json")
        .env("GOWORK", "off")
        .output()
        .map_err(|e| format!("spawn go analyze: {e}"))?;
    stdout_or_err(out, "go analyze")
}

fn stdout_or_err(out: std::process::Output, what: &str) -> Result<String, String> {
    if out.stdout.is_empty() {
        return Err(format!(
            "{what} produced no stdout (stderr: {})",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{what} stdout not utf8: {e}"))
}

/// Find the Go `aegis` binary: `$AEGIS_GO_BIN` if set, else build it from the
/// sibling `../aegis-cli` module into `target/aegis-go`.
fn locate_go_binary() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("AEGIS_GO_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("$AEGIS_GO_BIN={} is not a file", p.display()));
    }
    let repo = Path::new(GO_REPO);
    if !repo.join("go.mod").is_file() {
        return Err(format!(
            "{GO_REPO}/go.mod not found; set $AEGIS_GO_BIN to the Go aegis binary"
        ));
    }
    let target = std::fs::canonicalize("target")
        .map_err(|e| format!("resolve target/: {e}"))?
        .join("aegis-go");
    eprintln!("xtask: building Go binary from {GO_REPO} …");
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&target)
        .arg("./cmd/aegis")
        .current_dir(repo)
        .env("GOWORK", "off")
        .status()
        .map_err(|e| format!("go build: {e}"))?;
    if !status.success() {
        return Err("go build failed".to_string());
    }
    Ok(target)
}

fn read_dirs(dir: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect())
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_name_and_version() {
        assert_eq!(
            split_name_version("coa-2.0.3"),
            ("coa".into(), "2.0.3".into())
        );
        assert_eq!(
            split_name_version("node-ipc-11.0.0"),
            ("node-ipc".into(), "11.0.0".into())
        );
        assert_eq!(
            split_name_version("event-stream-3.3.6"),
            ("event-stream".into(), "3.3.6".into())
        );
        // leading v stripped
        assert_eq!(
            split_name_version("mod-v1.2.3"),
            ("mod".into(), "1.2.3".into())
        );
        // no version segment
        assert_eq!(
            split_name_version("justname"),
            ("justname".into(), "".into())
        );
    }

    #[test]
    fn norm_accepts_go_and_rust_score_keys() {
        let go =
            Norm::from_json(r#"{"verdict":"block","risk_score":140,"capabilities":["b","a"]}"#)
                .unwrap();
        let rust =
            Norm::from_json(r#"{"verdict":"block","score":140,"capabilities":["a","b"]}"#).unwrap();
        assert_eq!(go, rust);
        assert_eq!(go.capabilities, vec!["a".to_string(), "b".to_string()]);
    }
}
