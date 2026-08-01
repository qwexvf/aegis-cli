//! `aegis aur scan` — the PKGBUILD install gate.
//!
//! I/O shell around the pure `aegis-pkgbuild` scanner: reads a package
//! directory off disk, hands the bytes to `scan`, renders the result.
//!
//! The `--json` shape is the contract paru consumes (AEGIS-PLAN.txt §3.1).
//! Exit code reflects the verdict for direct CLI use, but a gate must
//! branch on the per-package verdict in the JSON, never on the exit code —
//! a batch run reports many packages through one process.

use std::path::Path;
use std::process::ExitCode;

use aegis_pkgbuild::{scan, LocalFile, Package, ScanResult, Verdict};
use serde::Serialize;

/// Leading bytes are all the scanner needs to identify a file format;
/// reading more would just be wasted I/O on a large committed blob.
const MAGIC_BYTES: usize = 8;

#[derive(Serialize)]
struct FindingJson<'a> {
    severity: &'a str,
    rule: &'a str,
    #[serde(rename = "where")]
    where_: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    evidence: &'a str,
}

#[derive(Serialize)]
struct ResultJson<'a> {
    package: &'a str,
    verdict: &'a str,
    findings: Vec<FindingJson<'a>>,
}

#[derive(Serialize)]
struct Report<'a> {
    results: Vec<ResultJson<'a>>,
}

pub(crate) fn run_aur_scan(dir: &str, json: bool) -> ExitCode {
    let path = Path::new(dir);
    let pkgbuild_path = path.join("PKGBUILD");
    let pkgbuild = match std::fs::read(&pkgbuild_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("aegis: {}: {e}", pkgbuild_path.display());
            return ExitCode::from(2);
        }
    };

    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let pkg = Package {
        upstream: aegis_pkgbuild::parse_upstream_url(&pkgbuild),
        name,
        pkgbuild,
        install: read_install_hooks(path),
        prev_pkgbuild: None,
        local_files: read_local_files(path),
    };

    let res = scan(&pkg);
    if json {
        if let Err(e) = print_json(&res) {
            eprintln!("aegis: json encode failed: {e}");
            return ExitCode::from(2);
        }
    } else {
        print_text(&res);
    }

    match res.verdict {
        Verdict::Block => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}

/// Every `*.install` file in the package directory, concatenated. These
/// run as root at pacman time, so they are scanned with the PKGBUILD.
fn read_install_hooks(dir: &Path) -> Vec<u8> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "install"))
        .collect();
    names.sort(); // deterministic output regardless of readdir order
    let mut out = Vec::new();
    for p in names {
        if let Ok(b) = std::fs::read(&p) {
            out.extend(b);
            out.push(b'\n');
        }
    }
    out
}

/// Files sitting in the package directory, with just enough leading bytes
/// for the magic-number check. Skips the PKGBUILD itself and the git dir.
fn read_local_files(dir: &Path) -> Vec<LocalFile> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<LocalFile> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().into_owned();
            if !p.is_file() || name == "PKGBUILD" || name.starts_with(".git") {
                return None;
            }
            let meta = std::fs::metadata(&p).ok()?;
            let bytes = std::fs::read(&p).ok()?;
            Some(LocalFile {
                name,
                head: bytes.into_iter().take(MAGIC_BYTES).collect(),
                size: meta.len(),
                // `added` needs the previous revision, which only the paru
                // gate has. Standalone scans cannot know, so stay quiet
                // rather than guess — local-binary-added is a diff rule.
                added: false,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn print_json(res: &ScanResult) -> Result<(), serde_json::Error> {
    let report = Report {
        results: vec![ResultJson {
            package: &res.package,
            verdict: res.verdict.name(),
            findings: res
                .findings
                .iter()
                .map(|f| FindingJson {
                    severity: f.severity.name(),
                    rule: f.rule,
                    where_: &f.where_,
                    message: &f.message,
                    evidence: &f.evidence,
                })
                .collect(),
        }],
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn print_text(res: &ScanResult) {
    let verdict = res.verdict.name().to_uppercase();
    println!("[aegis] {verdict} {}", res.package);
    if res.findings.is_empty() {
        println!("  no findings");
        return;
    }
    // Most severe first — a critical must not scroll off behind noise.
    let mut sorted: Vec<_> = res.findings.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in sorted {
        println!("  {:<8} {} — {}", f.severity.name(), f.where_, f.message);
        if !f.evidence.is_empty() {
            println!("    {}", f.evidence);
        }
    }
}
