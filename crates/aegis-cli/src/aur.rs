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
use serde::{Deserialize, Serialize};

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

/// One package in a batch request (AEGIS-PLAN.txt §3.2).
///
/// Unknown fields are rejected but every field except `dir` is optional, so
/// a caller can grow into the schema. The metadata fields are accepted and
/// currently unused — no implemented rule consumes them yet, and silently
/// ignoring them beats making paru's payload version-dependent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// The metadata fields below are parsed but not read yet — they exist so
// paru can send the full payload from day one and the rules that need them
// (maintainer-changed, typosquat weighting) can land without a protocol
// bump on both sides.
#[allow(dead_code)]
struct BatchPackage {
    #[serde(default)]
    name: String,
    dir: String,
    /// Files present in the previous revision. Anything on disk that is not
    /// in this list is treated as newly added, which is what the diff rules
    /// key on. Absent means "no previous revision known" — the diff rules
    /// then stay silent rather than reporting every file as new.
    #[serde(default)]
    prev_files: Option<Vec<String>>,
    #[serde(default)]
    prev_pkgbuild: Option<String>,
    /// "aur" (default) or "pkgbuild" for a -B / pkgbuild-repo target.
    #[serde(default)]
    kind: Option<String>,
    /// Commit author timestamps, newest first (`git log --format=%at`).
    #[serde(default)]
    commit_dates: Option<Vec<i64>>,
    /// `git rev-list --max-parents=0 HEAD | wc -l`.
    #[serde(default)]
    root_count: Option<usize>,
    /// Unix time to measure "recent" against. The caller supplies it so
    /// the scanner has no clock of its own and stays reproducible.
    #[serde(default)]
    now: Option<i64>,
    // --- accepted, not yet used by any rule ---
    #[serde(default)]
    maintainer: Option<String>,
    #[serde(default)]
    prev_maintainer: Option<String>,
    #[serde(default)]
    votes: Option<u64>,
    #[serde(default)]
    popularity: Option<f64>,
    #[serde(default)]
    out_of_date: Option<u64>,
    #[serde(default)]
    first_submitted: Option<i64>,
    #[serde(default)]
    last_modified: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    packages: Vec<BatchPackage>,
}

/// `aegis aur gate` — scan a whole transaction from one stdin payload.
///
/// Exits 0 whenever the scan itself succeeded, regardless of verdict;
/// non-zero is reserved for scanner failure so the caller can tell "this
/// package is bad" from "I could not tell you". The caller decides policy
/// from the per-package verdicts.
pub(crate) fn run_aur_gate() -> ExitCode {
    let mut raw = String::new();
    if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw) {
        eprintln!("aegis: read stdin: {e}");
        return ExitCode::from(2);
    }
    let req: BatchRequest = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aegis: malformed batch request: {e}");
            return ExitCode::from(2);
        }
    };

    let results: Vec<ScanResult> = req.packages.iter().map(scan_batch_entry).collect();
    for r in &results {
        let mut e = crate::audit::Entry::new("aur");
        e.ecosystem = "aur".into();
        e.package = r.package.clone();
        e.decision = r.verdict.name().to_string();
        crate::audit::write(&e);
    }
    let report = Report {
        results: results.iter().map(result_json).collect(),
    };
    match serde_json::to_string(&report) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("aegis: json encode failed: {e}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn scan_batch_entry(entry: &BatchPackage) -> ScanResult {
    let path = Path::new(&entry.dir);
    let pkgbuild = std::fs::read(path.join("PKGBUILD")).unwrap_or_default();
    let name = if entry.name.is_empty() {
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        entry.name.clone()
    };

    let mut local_files = read_local_files(path);
    // Mark newly-added files when the caller told us what was there before.
    if let Some(prev) = &entry.prev_files {
        for f in &mut local_files {
            f.added = !prev.contains(&f.name);
        }
    }

    // Only build a history when the caller actually supplied one; the
    // integrity rules stay silent rather than guessing from a default.
    let history = entry
        .commit_dates
        .as_ref()
        .map(|dates| aegis_pkgbuild::GitHistory {
            commit_dates: dates.clone(),
            root_count: entry.root_count.unwrap_or(1),
        });

    let pkg = Package {
        upstream: aegis_pkgbuild::parse_upstream_url(&pkgbuild),
        name,
        pkgbuild,
        install: read_install_hooks(path),
        prev_pkgbuild: entry.prev_pkgbuild.as_ref().map(|s| s.as_bytes().to_vec()),
        local_files,
        history,
        first_submitted: entry.first_submitted,
        now: entry.now,
    };
    let _ = &entry.kind; // reserved: -B targets are out of scope for v1
    scan(&pkg)
}

fn result_json(res: &ScanResult) -> ResultJson<'_> {
    ResultJson {
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
    }
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
        // A standalone scan has no AUR metadata and no caller-supplied
        // clock, so the history rules stay silent. `aur gate` carries them.
        history: None,
        first_submitted: None,
        now: None,
    };

    let res = scan(&pkg);
    {
        let mut e = crate::audit::Entry::new("aur");
        e.ecosystem = "aur".into();
        e.package = res.package.clone();
        e.decision = res.verdict.name().to_string();
        e.source = dir.to_string();
        crate::audit::write(&e);
    }
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

/// Files in the package directory, with just enough leading bytes for the
/// magic-number check. Skips the PKGBUILD itself and the git dir.
///
/// Recursive: a committed payload can sit in a subdirectory
/// (`tools/helper`) as easily as at the top level, and a non-recursive walk
/// simply does not see it. Names are relative to `dir` so they match what
/// `git ls-tree -r` reports and what `source=()` refers to.
fn read_local_files(dir: &Path) -> Vec<LocalFile> {
    let mut out = Vec::new();
    walk_local_files(dir, dir, 0, &mut out);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Depth cap so a symlink loop or a pathological tree cannot hang the gate.
const MAX_DEPTH: usize = 8;

fn walk_local_files(root: &Path, dir: &Path, depth: usize, out: &mut Vec<LocalFile>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().map(|s| s.to_string_lossy().into_owned()) else {
            continue;
        };
        if name.starts_with(".git") {
            continue;
        }
        // Do not follow symlinks — the target may live outside the package.
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            walk_local_files(root, &p, depth + 1, out);
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .into_owned();
        if rel == "PKGBUILD" {
            continue;
        }
        // Only the first bytes are needed; a committed blob may be large.
        let Ok(bytes) = read_head(&p, MAGIC_BYTES) else {
            continue;
        };
        out.push(LocalFile {
            name: rel,
            head: bytes,
            size: meta.len(),
            // `added` needs the previous revision, which only the paru gate
            // has. Standalone scans cannot know, so stay quiet rather than
            // guess — local-binary-added is a diff rule.
            added: false,
        });
    }
}

fn read_head(p: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

fn print_json(res: &ScanResult) -> Result<(), serde_json::Error> {
    let report = Report {
        results: vec![result_json(res)],
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

// --- G4: built-package inspection ---
//
// Runs after makepkg and before `pacman -U`. Text analysis of the PKGBUILD
// cannot see what the build actually produced; this can.

/// `aegis aur inspect <pkg.tar.zst>` — inspect a built pacman package.
pub(crate) fn run_pkg_inspect(file: &str, json: bool) -> ExitCode {
    let entries = match read_pkg_entries(Path::new(file)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("aegis: {file}: {e}");
            return ExitCode::from(2);
        }
    };
    let name = Path::new(file)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let res = aegis_pkgbuild::inspect_package(&name, &entries);

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

/// Read the tar member list out of a pacman package.
///
/// Only the headers are needed — never the file bodies — so this streams
/// and does not extract anything to disk.
fn read_pkg_entries(path: &Path) -> Result<Vec<aegis_pkgbuild::PkgEntry>, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let name = path.to_string_lossy();
    let reader: Box<dyn std::io::Read> = if name.ends_with(".zst") {
        Box::new(
            ruzstd::decoding::StreamingDecoder::new(std::io::BufReader::new(f))
                .map_err(|e| format!("zstd: {e}"))?,
        )
    } else if name.ends_with(".gz") {
        Box::new(flate2::read::GzDecoder::new(f))
    } else if name.ends_with(".tar") {
        Box::new(f)
    } else {
        // .xz needs a C liblzma; pacman has defaulted to zstd since 2020.
        return Err("unsupported compression (expected .zst, .gz or .tar)".into());
    };

    let mut archive = tar::Archive::new(reader);
    let mut out = Vec::new();
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let header = entry.header();
        out.push(aegis_pkgbuild::PkgEntry {
            path: entry
                .path()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .into_owned(),
            mode: header.mode().unwrap_or(0),
            size: header.size().unwrap_or(0),
        });
    }
    Ok(out)
}
