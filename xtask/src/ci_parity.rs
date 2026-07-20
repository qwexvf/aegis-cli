//! `xtask ci-parity [--record]` — the ci-command parity gate.
//!
//! Walks the pinned lockfile corpus (`examples/ci-parity/<fixture>/`), runs the
//! Rust `aegis ci <lockfile> --json` on each, and compares its normalized
//! report against a committed golden (`<fixture>/ci.golden.json`). Exit non-zero
//! if any fixture diverges.
//!
//! `ci` enrich hits the network (fetches each dep's tarball + queries OSV/
//! EPSS/KEV), so making this an offline CI gate needs two recorded halves: the
//! Go-captured golden (`--record`, needs the Go binary + network) and an HTTP
//! cassette of the Rust `ci` run (`--record-cassettes`, needs network once)
//! under [`CASSETTE_DIR`]. With both committed, the plain check runs the Rust
//! binary against the replayed cassette (`AEGIS_HTTP_REPLAY`) — fully offline +
//! deterministic, so it now runs in the blocking CI `parity` job alongside
//! analyze/sbom.
//!
//! ## The Go/Rust invocation bridge
//!
//! Go `ci` autodetects the lockfile in the *current directory* and writes an
//! `aegis.lock` side-effect; Rust `ci` takes the lockfile as a positional path.
//! At `--record` we copy the fixture's lockfile into a scratch dir and run Go
//! there (so the committed fixture stays clean), then normalize its `--json`.
//!
//! ## What the golden compares (drift-stable subset)
//!
//! The normalized report drops fields that legitimately drift between runs of a
//! frozen package version: `project` (dir-name coupled), and every advisory's
//! `epss` / `epss_percentile` (FIRST.org rescored daily) / `summary` / `url`.
//! It keeps the verdict-defining core: `fail_on`, `enriched`, `passed`, the
//! summary counts, and per-dep `{verdict, risk_score, flags, advisory ids +
//! severities}`. Newly-disclosed advisories for a pinned version are rare but
//! possible — refresh the golden with `--record` when they land.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

const CORPUS: &str = "examples/ci-parity";
/// Shared HTTP cassette for every fixture's Rust `ci` run — outside CORPUS so
/// it is not mistaken for a fixture dir. One dir dedupes shared responses (the
/// ~1 MB KEV feed is stored once, not per fixture); requests key on body so
/// per-fixture OSV/EPSS batch POSTs still map to distinct entries.
const CASSETTE_DIR: &str = "examples/ci-parity-cassettes";

// ── normalized (comparable) report ──────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CiNorm {
    fail_on: String,
    enriched: bool,
    passed: bool,
    summary: SummaryN,
    findings: Vec<FindingN>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SummaryN {
    total: i64,
    safe: i64,
    review: i64,
    prompt: i64,
    blocked: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct FindingN {
    ecosystem: String,
    name: String,
    version: String,
    direct: bool,
    verdict: String,
    risk_score: i64,
    flags: Vec<FlagN>,
    advisories: Vec<AdvN>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct FlagN {
    code: String,
    weight: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct AdvN {
    id: String,
    severity: String,
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fixed_in: Option<String>,
}

// ── raw wire shape (identical for Go + Rust) ─────────────────────────────────

#[derive(Deserialize)]
struct RawCi {
    #[serde(default)]
    fail_on: String,
    #[serde(default)]
    enriched: bool,
    #[serde(default)]
    passed: bool,
    #[serde(default)]
    summary: RawSummary,
    #[serde(default)]
    findings: Vec<RawFinding>,
}

#[derive(Deserialize, Default)]
struct RawSummary {
    #[serde(default)]
    total: i64,
    #[serde(default)]
    safe: i64,
    #[serde(default)]
    review: i64,
    #[serde(default)]
    prompt: i64,
    #[serde(default)]
    blocked: i64,
}

#[derive(Deserialize)]
struct RawFinding {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    direct: bool,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    risk_score: i64,
    #[serde(default)]
    flags: Vec<RawFlag>,
    #[serde(default)]
    advisories: Vec<RawAdv>,
}

#[derive(Deserialize)]
struct RawFlag {
    #[serde(default)]
    code: String,
    #[serde(default)]
    weight: i64,
}

#[derive(Deserialize)]
struct RawAdv {
    #[serde(default)]
    id: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    fixed_in: Option<String>,
}

impl CiNorm {
    fn from_json(s: &str) -> Result<CiNorm, String> {
        let r: RawCi = serde_json::from_str(s).map_err(|e| format!("parse ci json: {e}"))?;
        let mut findings: Vec<FindingN> = r
            .findings
            .into_iter()
            .map(|f| {
                let mut flags: Vec<FlagN> = f
                    .flags
                    .into_iter()
                    .map(|x| FlagN {
                        code: x.code,
                        weight: x.weight,
                    })
                    .collect();
                flags.sort_by(|a, b| a.code.cmp(&b.code));
                let mut advisories: Vec<AdvN> = f
                    .advisories
                    .into_iter()
                    .map(|a| AdvN {
                        id: a.id,
                        severity: a.severity,
                        source: a.source,
                        fixed_in: a.fixed_in,
                    })
                    .collect();
                advisories.sort_by(|a, b| a.id.cmp(&b.id));
                // Go v0.29 enriches (fetches + capability-scans) ONLY npm; Rust
                // also enriches pypi/crates (Rust-ahead). Go has no capability
                // signal for non-npm, so for those ecosystems compare the
                // Go-comparable surface only — verdict + advisories — and drop
                // Rust's additive capability flags/score. npm stays a full
                // Go-vs-Rust comparison.
                let go_can_enrich = f.ecosystem == "npm";
                let (flags, risk_score) = if go_can_enrich {
                    (flags, f.risk_score)
                } else {
                    (Vec::new(), 0)
                };
                FindingN {
                    ecosystem: f.ecosystem,
                    name: f.name,
                    version: f.version,
                    direct: f.direct,
                    verdict: f.verdict,
                    risk_score,
                    flags,
                    advisories,
                }
            })
            .collect();
        findings.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        Ok(CiNorm {
            fail_on: r.fail_on,
            enriched: r.enriched,
            passed: r.passed,
            summary: SummaryN {
                total: r.summary.total,
                safe: r.summary.safe,
                review: r.summary.review,
                prompt: r.summary.prompt,
                blocked: r.summary.blocked,
            },
            findings,
        })
    }
}

// ── fixtures ────────────────────────────────────────────────────────────────

/// One lockfile fixture: its dir, the lockfile inside it, and its golden.
struct Fixture {
    name: String,
    lockfile: PathBuf,
    golden: PathBuf,
}

pub fn run(record: bool, record_cassettes: bool) -> std::process::ExitCode {
    let fixtures = match discover() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("xtask: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    if fixtures.is_empty() {
        eprintln!("xtask: no fixtures under {CORPUS}");
        return std::process::ExitCode::from(2);
    }

    // Capture the shared HTTP cassette by running each Rust `ci` live once.
    if record_cassettes {
        return record_cassettes_run(&fixtures);
    }

    let go_bin = if record {
        match crate::analyze_parity::locate_go_binary() {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("xtask: --record needs the Go binary: {e}");
                return std::process::ExitCode::from(2);
            }
        }
    } else {
        None
    };

    let mut pass = 0usize;
    let mut fail = 0usize;
    for f in &fixtures {
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
    println!("\nci-parity: {pass}/{} match", pass + fail);
    if fail == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

/// Enumerate fixture dirs: each direct child of `examples/ci-parity/` holding a
/// lockfile (the single non-golden file) becomes a fixture.
fn discover() -> Result<Vec<Fixture>, String> {
    let root = Path::new(CORPUS);
    if !root.is_dir() {
        return Err(format!("{CORPUS} not found (run from the repo root)"));
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|e| format!("read {CORPUS}: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    let mut out = Vec::new();
    for dir in dirs {
        let lockfile = find_lockfile(&dir)?;
        out.push(Fixture {
            name: file_name(&dir),
            golden: dir.join("ci.golden.json"),
            lockfile,
        });
    }
    Ok(out)
}

/// Recognized lockfile basenames (the ones `aegis ci` can parse). A fixture may
/// also carry consuming source (e.g. `index.js`) — those are not lockfiles.
const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "Cargo.lock",
    "go.sum",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "packages.lock.json",
];

/// Find the lockfile in a fixture dir by matching a known lockfile basename.
fn find_lockfile(dir: &Path) -> Result<PathBuf, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && LOCKFILE_NAMES.contains(&file_name(p).as_str()))
        .collect();
    files.sort();
    files
        .into_iter()
        .next()
        .ok_or_else(|| format!("{}: no recognized lockfile", dir.display()))
}

fn check_one(f: &Fixture, go_bin: Option<&Path>, record: bool) -> Result<String, String> {
    if record {
        let go = go_bin.ok_or("no Go binary")?;
        let out = run_go_ci(go, f)?;
        let norm = CiNorm::from_json(&out)?;
        let json =
            serde_json::to_string_pretty(&norm).map_err(|e| format!("encode golden: {e}"))?;
        std::fs::write(&f.golden, json + "\n")
            .map_err(|e| format!("write {}: {e}", f.golden.display()))?;
        return Ok(format!(
            "recorded (passed={}, findings={})",
            norm.passed,
            norm.findings.len()
        ));
    }

    let rust_out = run_rust_ci(f, ("AEGIS_HTTP_REPLAY", CASSETTE_DIR))?;
    let rust = CiNorm::from_json(&rust_out)?;
    let golden_str = std::fs::read_to_string(&f.golden)
        .map_err(|e| format!("read golden {} (record first?): {e}", f.golden.display()))?;
    let golden: CiNorm =
        serde_json::from_str(&golden_str).map_err(|e| format!("parse golden: {e}"))?;

    if rust == golden {
        Ok(format!(
            "passed={}, findings={}",
            rust.passed,
            rust.findings.len()
        ))
    } else {
        Err(format!("DIVERGED\n{}", diff_summary(&golden, &rust)))
    }
}

/// Human-readable first-divergence summary for a failed comparison.
fn diff_summary(golden: &CiNorm, rust: &CiNorm) -> String {
    if golden.passed != rust.passed || golden.summary != rust.summary {
        return format!(
            "       golden: passed={}, summary={:?}\n       rust:   passed={}, summary={:?}",
            golden.passed, golden.summary, rust.passed, rust.summary
        );
    }
    // Same top-line — dig into per-finding differences.
    for (g, r) in golden.findings.iter().zip(rust.findings.iter()) {
        if g != r {
            let g_adv: Vec<&str> = g.advisories.iter().map(|a| a.id.as_str()).collect();
            let r_adv: Vec<&str> = r.advisories.iter().map(|a| a.id.as_str()).collect();
            return format!(
                "       {} {}:\n       golden: v={}, s={}, flags={:?}, adv={:?}\n       rust:   v={}, s={}, flags={:?}, adv={:?}",
                g.name,
                g.version,
                g.verdict,
                g.risk_score,
                g.flags.iter().map(|f| &f.code).collect::<Vec<_>>(),
                g_adv,
                r.verdict,
                r.risk_score,
                r.flags.iter().map(|f| &f.code).collect::<Vec<_>>(),
                r_adv,
            );
        }
    }
    if golden.findings.len() != rust.findings.len() {
        return format!(
            "       finding count: golden={}, rust={}",
            golden.findings.len(),
            rust.findings.len()
        );
    }
    "       (fields differ — fail_on/enriched)".to_string()
}

/// Run the Rust `ci` on a fixture. `http_env` sets AEGIS_HTTP_REPLAY (offline
/// check) or AEGIS_HTTP_RECORD (capture). Both use a fresh cache dir so the
/// on-disk advisory/KEV cache never shadows the HTTP call, and drop
/// GITHUB_TOKEN so the GHSA path stays out of both record and replay.
fn run_rust_ci(f: &Fixture, http_env: (&str, &str)) -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let cache = std::env::temp_dir().join("aegis-ci-parity-xdg");
    let _ = std::fs::remove_dir_all(&cache);
    let out = Command::new(cargo)
        .args(["run", "-q", "-p", "aegis-cli", "--", "ci"])
        .arg(&f.lockfile)
        .arg("--json")
        .env(http_env.0, http_env.1)
        .env("XDG_CACHE_HOME", &cache)
        .env_remove("GITHUB_TOKEN")
        .output()
        .map_err(|e| format!("spawn rust ci: {e}"))?;
    // ci exits 1 on findings; stdout still carries the report.
    stdout_or_err(out, "rust ci")
}

/// `--record-cassettes`: run each fixture's Rust `ci` live once, persisting the
/// HTTP traffic into the shared [`CASSETTE_DIR`] so the plain check can replay
/// it offline. Needs network; commit the resulting dir.
fn record_cassettes_run(fixtures: &[Fixture]) -> std::process::ExitCode {
    let _ = std::fs::remove_dir_all(CASSETTE_DIR);
    for f in fixtures {
        match run_rust_ci(f, ("AEGIS_HTTP_RECORD", CASSETTE_DIR)) {
            Ok(_) => println!("  rec  {} — captured", f.name),
            Err(e) => {
                println!("  FAIL {} — {e}", f.name);
                return std::process::ExitCode::from(1);
            }
        }
    }
    let n = std::fs::read_dir(CASSETTE_DIR)
        .map(|d| d.count())
        .unwrap_or(0);
    println!("\nrecorded {n} cassette entr(ies) under {CASSETTE_DIR}");
    std::process::ExitCode::SUCCESS
}

/// Run Go `ci` in a scratch copy of the fixture so its `aegis.lock` side-effect
/// and cwd-lockfile autodetect don't touch the committed fixture.
fn run_go_ci(go: &Path, f: &Fixture) -> Result<String, String> {
    let scratch = std::env::temp_dir().join("aegis-ci-parity").join(&f.name);
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("mkdir scratch: {e}"))?;
    // Copy the whole fixture (lockfile + any consuming source like index.js),
    // minus the golden. Go's ci runs a usage analysis over the project dir: a
    // dep imported by the source is `Used` (full verdict), a bare lockfile with
    // no source marks every dep `Unused` and downgrades it. The source files
    // pin the fixture to the realistic "dep is used" path.
    let fixture_dir = f
        .lockfile
        .parent()
        .ok_or("fixture lockfile has no parent dir")?;
    for entry in std::fs::read_dir(fixture_dir).map_err(|e| format!("read fixture: {e}"))? {
        let entry = entry.map_err(|e| format!("fixture entry: {e}"))?;
        let path = entry.path();
        if !path.is_file() || file_name(&path) == "ci.golden.json" {
            continue;
        }
        std::fs::copy(&path, scratch.join(file_name(&path)))
            .map_err(|e| format!("copy {}: {e}", path.display()))?;
    }

    // Pin a fresh cache dir per record: Go's default `~/.aegis/cache` can hold
    // advisory docs parsed by an older build, which serves stale `fixed_in` and
    // corrupts the golden. A clean cache forces a live OSV re-fetch.
    let cache = scratch.join("cache");
    let out = Command::new(go)
        .args(["ci", "--json"])
        .current_dir(&scratch)
        .env("GOWORK", "off")
        .env("AEGIS_CACHE_DIR", &cache)
        .output()
        .map_err(|e| format!("spawn go ci: {e}"))?;
    stdout_or_err(out, "go ci")
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

fn file_name(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GO_LODASH: &str = r#"{"project":"lodash","fail_on":"block","enriched":true,"passed":false,"summary":{"total":1,"safe":0,"review":0,"prompt":0,"blocked":1},"findings":[{"ecosystem":"npm","name":"lodash","version":"4.17.4","direct":false,"verdict":"block","risk_score":55,"flags":[{"code":"unlisted-large-file","detail":"…","weight":55}],"advisories":[{"id":"GHSA-35jh-r3h4-6jhm","severity":"high","summary":"Command Injection","url":"u","source":"osv","epss":0.2241,"epss_percentile":0.97431},{"id":"GHSA-29mw-wpgm-hmr9","severity":"medium","summary":"ReDoS","url":"u","source":"osv","epss":0.07336,"epss_percentile":0.93702}]}]}"#;

    // Same package, EPSS rescored + advisory order shuffled — must normalize equal.
    const RUST_LODASH: &str = r#"{"project":"whatever-dir","fail_on":"block","enriched":true,"passed":false,"summary":{"total":1,"safe":0,"review":0,"prompt":0,"blocked":1},"findings":[{"ecosystem":"npm","name":"lodash","version":"4.17.4","direct":false,"verdict":"block","risk_score":55,"flags":[{"code":"unlisted-large-file","detail":"…","weight":55}],"advisories":[{"id":"GHSA-29mw-wpgm-hmr9","severity":"medium","summary":"ReDoS","url":"u2","source":"osv","epss":0.99,"epss_percentile":0.99},{"id":"GHSA-35jh-r3h4-6jhm","severity":"high","summary":"Command Injection","url":"u2","source":"osv","epss":0.11,"epss_percentile":0.5}]}]}"#;

    #[test]
    fn epss_and_project_and_order_are_normalized_out() {
        let go = CiNorm::from_json(GO_LODASH).unwrap();
        let rust = CiNorm::from_json(RUST_LODASH).unwrap();
        assert_eq!(go, rust);
    }

    #[test]
    fn advisories_sorted_by_id() {
        let n = CiNorm::from_json(GO_LODASH).unwrap();
        let ids: Vec<&str> = n.findings[0]
            .advisories
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(ids, vec!["GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm"]);
    }

    #[test]
    fn differing_verdict_is_caught() {
        let go = CiNorm::from_json(GO_LODASH).unwrap();
        let flipped = RUST_LODASH.replace("\"verdict\":\"block\"", "\"verdict\":\"review\"");
        let rust = CiNorm::from_json(&flipped).unwrap();
        assert_ne!(go, rust);
    }
}
