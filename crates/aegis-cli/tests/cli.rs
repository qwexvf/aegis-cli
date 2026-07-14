//! Integration tests that drive the real `aegis` binary end-to-end.
//! Network-free: only `parse`, `analyze`, and `run` with source-scan
//! checks (ast/heuristics) — no OSV lookup — so they're deterministic
//! and run offline in CI.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_aegis");

/// Unique temp dir per test (no rand/time dep).
fn tmp(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "aegis-cli-it-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &PathBuf, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

struct Out {
    code: i32,
    stdout: String,
}

fn run(args: &[&str]) -> Out {
    let o = Command::new(BIN).args(args).output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
    }
}

#[test]
fn parse_lockfile_json() {
    let d = tmp("parse");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    );
    let out = run(&[
        "parse",
        d.join("package-lock.json").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"name\": \"lodash\""),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("\"version\": \"4.17.21\""));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn parse_unknown_file_exits_2() {
    let out = run(&["parse", "/nonexistent/nope.lock"]);
    assert_eq!(out.code, 2);
}

#[test]
fn analyze_malicious_js_blocks() {
    let d = tmp("analyze");
    write(
        &d,
        "index.js",
        "const cp = require('child_process');\neval(atob('ZXZpbA=='));\n",
    );
    let out = run(&[
        "analyze",
        d.to_str().unwrap(),
        "--ecosystem",
        "npm",
        "--json",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"verdict\": \"block\""),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("shell-spawn"));
    assert!(out.stdout.contains("dynamic-eval"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn analyze_clean_code_is_safe() {
    let d = tmp("clean");
    write(&d, "index.js", "export const add = (a, b) => a + b;\n");
    let out = run(&["analyze", d.to_str().unwrap(), "--json"]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"verdict\": \"safe\""),
        "{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn run_config_parallel_source_tasks_fail_on_block() {
    let d = tmp("run");
    // two malicious package dirs + one clean, all scanned via source checks only.
    std::fs::create_dir_all(d.join("evil1")).unwrap();
    std::fs::create_dir_all(d.join("evil2")).unwrap();
    std::fs::create_dir_all(d.join("good")).unwrap();
    write(&d.join("evil1"), "a.js", "eval(atob('eA=='))");
    write(&d.join("evil2"), "b.py", "import os\nos.system('rm -rf /')");
    write(&d.join("good"), "c.js", "export const x = 1;");

    let cfg = format!(
        r#"
[[task]]
name = "evil1"
path = "{p}/evil1"
ecosystem = "npm"
checks = ["ast", "heuristics"]

[[task]]
name = "evil2"
path = "{p}/evil2"
ecosystem = "pypi"
checks = ["ast", "heuristics"]

[[task]]
name = "good"
path = "{p}/good"
ecosystem = "npm"
checks = ["ast", "heuristics"]
"#,
        p = d.to_str().unwrap()
    );
    write(&d, "aegis.toml", &cfg);

    let out = run(&["run", d.join("aegis.toml").to_str().unwrap(), "--json"]);
    // Any BLOCK task → overall fail → exit 1.
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.contains("\"failed\": true"), "{}", out.stdout);
    // The clean task should not fail.
    assert!(out.stdout.contains("\"name\": \"good\""));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn run_missing_config_exits_2() {
    let out = run(&["run", "/nonexistent/aegis.toml"]);
    assert_eq!(out.code, 2);
}
