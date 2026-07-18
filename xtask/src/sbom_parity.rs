//! `xtask sbom-parity [--record]` — the sbom-command parity gate.
//!
//! Walks the pinned lockfile corpus (`examples/sbom-parity/<fixture>/`), runs
//! Rust `sbom <lockfile> --format {cyclonedx,spdx}` on each, and compares its
//! output against committed goldens (`cyclonedx.golden.json` /
//! `spdx.golden.json`). Exit non-zero if any diverges.
//!
//! Unlike `ci-parity`, `sbom` is fully offline + deterministic, so this gate
//! needs no network at check time and no Go toolchain (goldens are committed) —
//! it belongs in the blocking CI job alongside `analyze-parity`.
//!
//! ## The Go/Rust invocation bridge
//!
//! Go `sbom` builds from `aegis.lock` (the snapshot model); Rust `sbom` takes
//! the lockfile as a positional path. At `--record` we copy the fixture's
//! lockfile into a scratch dir, run Go `snapshot save` (offline) to write
//! `aegis.lock`, then `go sbom`. Both are invoked with a fixed `--project` name
//! so the root component / document identity lines up.
//!
//! ## What the comparison scrubs
//!
//! Provenance fields that legitimately vary run-to-run are removed before the
//! structural diff: CycloneDX `serialNumber`, `metadata.timestamp`,
//! `metadata.tools` (tool version); SPDX `documentNamespace`, `creationInfo`
//! (timestamp + tool version). Everything else — components / packages, purls,
//! hashes, licenses, and the dependency / relationship graph — must match.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const CORPUS: &str = "examples/sbom-parity";
/// Fixed root-component / document name passed to both tools so the BOM's
/// self-identity (which otherwise defaults to the project dir name) matches.
const PROJECT: &str = "sbomparity";

/// (format flag, golden filename).
const FORMATS: &[(&str, &str)] = &[
    ("cyclonedx", "cyclonedx.golden.json"),
    ("spdx", "spdx.golden.json"),
];

struct Fixture {
    name: String,
    lockfile: PathBuf,
    dir: PathBuf,
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
        eprintln!("xtask: no fixtures under {CORPUS}");
        return std::process::ExitCode::from(2);
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
        for (fmt, golden_name) in FORMATS {
            let golden = f.dir.join(golden_name);
            let label = format!("{} [{fmt}]", f.name);
            match check_one(f, fmt, &golden, go_bin.as_deref(), record) {
                Ok(msg) => {
                    pass += 1;
                    println!("  ok   {label} — {msg}");
                }
                Err(msg) => {
                    fail += 1;
                    println!("  FAIL {label} — {msg}");
                }
            }
        }
    }

    if record {
        println!("\nrecorded {pass} golden(s)");
        return std::process::ExitCode::SUCCESS;
    }
    println!("\nsbom-parity: {pass}/{} match", pass + fail);
    if fail == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

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
            lockfile,
            dir,
        });
    }
    Ok(out)
}

const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
    "requirements.txt",
    "Gemfile.lock",
    "composer.lock",
];

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

fn check_one(
    f: &Fixture,
    fmt: &str,
    golden: &Path,
    go_bin: Option<&Path>,
    record: bool,
) -> Result<String, String> {
    if record {
        let go = go_bin.ok_or("no Go binary")?;
        let raw = run_go_sbom(go, f, fmt)?;
        let scrubbed = scrub(fmt, parse(&raw)?);
        let json =
            serde_json::to_string_pretty(&scrubbed).map_err(|e| format!("encode golden: {e}"))?;
        std::fs::write(golden, json + "\n")
            .map_err(|e| format!("write {}: {e}", golden.display()))?;
        let n = component_count(fmt, &scrubbed);
        return Ok(format!("recorded ({n} entries)"));
    }

    let raw = run_rust_sbom(f, fmt)?;
    let actual = scrub(fmt, parse(&raw)?);
    let golden_val: Value = parse(
        &std::fs::read_to_string(golden)
            .map_err(|e| format!("read golden {} (record first?): {e}", golden.display()))?,
    )?;
    match crate::jsondiff::diff(&golden_val, &actual) {
        None => Ok(format!("{} entries", component_count(fmt, &actual))),
        Some(m) => Err(format!("DIVERGED\n{m}")),
    }
}

fn parse(s: &str) -> Result<Value, String> {
    serde_json::from_str(s).map_err(|e| format!("parse sbom json: {e}"))
}

/// Remove provenance fields that vary run-to-run (timestamps, serial/namespace
/// UUIDs, tool version) so the diff sees only the SBOM content.
fn scrub(fmt: &str, mut v: Value) -> Value {
    if let Some(obj) = v.as_object_mut() {
        match fmt {
            "cyclonedx" => {
                obj.remove("serialNumber");
                if let Some(meta) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
                    meta.remove("timestamp");
                    meta.remove("tools");
                }
            }
            "spdx" => {
                obj.remove("documentNamespace");
                obj.remove("creationInfo");
            }
            _ => {}
        }
    }
    v
}

fn component_count(fmt: &str, v: &Value) -> usize {
    let key = if fmt == "spdx" {
        "packages"
    } else {
        "components"
    };
    v.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

fn run_rust_sbom(f: &Fixture, fmt: &str) -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(["run", "-q", "-p", "aegis-cli", "--", "sbom"])
        .arg(&f.lockfile)
        .args(["--project", PROJECT, "--format", fmt])
        .output()
        .map_err(|e| format!("spawn rust sbom: {e}"))?;
    stdout_or_err(out, "rust sbom")
}

/// Go `sbom` reads `aegis.lock`, so copy the lockfile into a scratch dir, run
/// `snapshot save` (offline) to produce it, then emit the SBOM there.
fn run_go_sbom(go: &Path, f: &Fixture, fmt: &str) -> Result<String, String> {
    let scratch = std::env::temp_dir().join("aegis-sbom-parity").join(&f.name);
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("mkdir scratch: {e}"))?;
    std::fs::copy(&f.lockfile, scratch.join(file_name(&f.lockfile)))
        .map_err(|e| format!("copy lockfile: {e}"))?;
    let cache = scratch.join("cache");

    let save = Command::new(go)
        .arg("snapshot")
        .arg("save")
        .current_dir(&scratch)
        .env("GOWORK", "off")
        .env("AEGIS_CACHE_DIR", &cache)
        .output()
        .map_err(|e| format!("spawn go snapshot save: {e}"))?;
    if !save.status.success() {
        return Err(format!(
            "go snapshot save failed: {}",
            String::from_utf8_lossy(&save.stderr).trim()
        ));
    }

    let out = Command::new(go)
        .args(["sbom", "--project", PROJECT, "--format", fmt, "--pretty"])
        .current_dir(&scratch)
        .env("GOWORK", "off")
        .env("AEGIS_CACHE_DIR", &cache)
        .output()
        .map_err(|e| format!("spawn go sbom: {e}"))?;
    stdout_or_err(out, "go sbom")
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

    #[test]
    fn scrub_drops_cyclonedx_provenance() {
        let v = serde_json::json!({
            "serialNumber": "urn:uuid:abc",
            "specVersion": "1.5",
            "metadata": {"timestamp": "2026-01-01T00:00:00Z", "tools": {}, "component": {"name": "x"}},
            "components": [{"name": "lodash"}]
        });
        let s = scrub("cyclonedx", v);
        assert!(s.get("serialNumber").is_none());
        assert!(s["metadata"].get("timestamp").is_none());
        assert!(s["metadata"].get("tools").is_none());
        // content survives
        assert_eq!(s["specVersion"], "1.5");
        assert_eq!(s["components"][0]["name"], "lodash");
        assert_eq!(s["metadata"]["component"]["name"], "x");
    }

    #[test]
    fn scrub_drops_spdx_provenance() {
        let v = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://x/uuid",
            "creationInfo": {"created": "2026-01-01T00:00:00Z"},
            "packages": [{"name": "lodash"}]
        });
        let s = scrub("spdx", v);
        assert!(s.get("documentNamespace").is_none());
        assert!(s.get("creationInfo").is_none());
        assert_eq!(s["spdxVersion"], "SPDX-2.3");
        assert_eq!(s["packages"][0]["name"], "lodash");
    }
}
