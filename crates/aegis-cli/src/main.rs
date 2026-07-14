//! The `aegis` CLI (Rust port). First runnable slice: parse a lockfile
//! through `aegis-lockfile` and report its dependencies. More commands
//! (enrich, ci, analyze) land as the usecase layer is ported.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use aegis_ast::{scanner_for, Findings, LanguageScanner};
use aegis_domain::{
    risk_score, verdict, AdvisoryQuery, CapabilitySet, Dependency, Ecosystem, Fingerprint,
    RiskAssessment, Severity,
};
use aegis_heuristics::{run_heuristics, NormalizedPackage};
use aegis_lockfile::{parse_file, DirectMap};
use aegis_net::UreqClient;
use aegis_vuln::{EpssClient, KevCatalog, OsvClient};
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use serde::Serialize;

#[derive(Parser)]
#[command(name = "aegis", version, about = "Supply-chain security scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a single lockfile and list its dependencies.
    Parse {
        /// Path to the lockfile (e.g. package-lock.json, Cargo.lock).
        file: String,
        /// Emit machine-readable JSON instead of a text table.
        #[arg(long)]
        json: bool,
    },
    /// CI gate: parse a lockfile, look up CVEs (OSV), fail on findings.
    Ci {
        /// Path to the lockfile.
        file: String,
        /// Severity threshold to fail on: critical, high, medium, low.
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Skip the network CVE lookup (offline / air-gapped).
        #[arg(long)]
        offline: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan a package source directory (AST + heuristics) and score it.
    Analyze {
        /// Directory containing the package's source tree.
        dir: String,
        /// Package name (used by name-based heuristics like typosquat).
        #[arg(long)]
        name: Option<String>,
        /// Ecosystem for heuristics: npm, pypi, crates, go, …
        #[arg(long, default_value = "npm")]
        ecosystem: String,
        /// Emit machine-readable JSON instead of a text summary.
        #[arg(long)]
        json: bool,
    },
}

/// JSON/serialization view of a dependency (domain `Dependency` stays
/// serde-free, so the CLI owns its wire shape).
#[derive(Serialize)]
struct DepView {
    ecosystem: String,
    name: String,
    version: String,
    direct: bool,
}

impl From<&Dependency> for DepView {
    fn from(d: &Dependency) -> Self {
        DepView {
            ecosystem: d.ecosystem.as_str().to_string(),
            name: d.name.clone(),
            version: d.version.clone(),
            direct: d.direct,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Parse { file, json } => run_parse(&file, json),
        Command::Ci {
            file,
            fail_on,
            offline,
            json,
        } => run_ci(&file, &fail_on, offline, json),
        Command::Analyze {
            dir,
            name,
            ecosystem,
            json,
        } => run_analyze(&dir, name.as_deref(), &ecosystem, json),
    }
}

// --- ci ------------------------------------------------------------

/// Severity ordering for the fail-on threshold (higher = more severe).
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => return None,
    })
}

#[derive(Serialize)]
struct FindingView {
    ecosystem: String,
    name: String,
    version: String,
    advisory: String,
    severity: String,
    summary: String,
    fixed_in: String,
    /// EPSS exploit probability (0–1); 0 = unscored.
    epss: f64,
    /// true when the CVE is in CISA's Known Exploited Vulnerabilities catalog.
    in_kev: bool,
}

#[derive(Serialize)]
struct CiView {
    fail_on: String,
    failed: bool,
    findings: Vec<FindingView>,
}

fn run_ci(file: &str, fail_on: &str, offline: bool, json: bool) -> ExitCode {
    let Some(threshold) = parse_severity(fail_on) else {
        eprintln!("aegis: unknown --fail-on severity: {fail_on}");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("aegis: cannot read {file}: {e}");
            return ExitCode::from(2);
        }
    };
    let basename = Path::new(file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file);
    let deps = match parse_file(basename, &bytes, &DirectMap::new()) {
        Ok(Some(d)) => d,
        Ok(None) => {
            eprintln!("aegis: no parser for lockfile '{basename}'");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: failed to parse {basename}: {e}");
            return ExitCode::from(2);
        }
    };

    // Look up CVEs unless offline.
    let queries: Vec<AdvisoryQuery> = deps
        .iter()
        .filter(|d| !d.version.is_empty())
        .map(|d| AdvisoryQuery {
            ecosystem: d.ecosystem,
            name: d.name.clone(),
            version: d.version.clone(),
        })
        .collect();

    let mut findings: Vec<FindingView> = Vec::new();
    if !offline {
        let client = UreqClient::new();
        let results = match OsvClient::default().lookup(&client, &queries) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("aegis: CVE lookup failed: {e}");
                return ExitCode::from(2);
            }
        };

        // Flatten advisories, keeping each one's (eco, name, version) context.
        let mut advisories = Vec::new();
        let mut context: Vec<(String, String, String)> = Vec::new();
        for q in &queries {
            for adv in results.get(&q.key()).map(|v| v.as_slice()).unwrap_or(&[]) {
                advisories.push(adv.clone());
                context.push((
                    q.ecosystem.as_str().to_string(),
                    q.name.clone(),
                    q.version.clone(),
                ));
            }
        }

        // Enrich: EPSS probability + CISA KEV flag (best-effort, order-preserving).
        advisories = EpssClient::default().enrich_advisories(&client, advisories);
        advisories = KevCatalog::default().enrich_advisories(&client, advisories);

        for (adv, (eco, name, version)) in advisories.into_iter().zip(context) {
            findings.push(FindingView {
                ecosystem: eco,
                name,
                version,
                advisory: adv.id,
                severity: adv.severity.as_str().to_string(),
                summary: adv.summary,
                fixed_in: adv.fixed_in,
                epss: adv.epss,
                in_kev: adv.in_kev,
            });
        }
    }

    // Gate: fail when any finding meets the severity threshold.
    let failed = findings.iter().any(|f| {
        parse_severity(&f.severity)
            .map(|s| severity_rank(s) >= severity_rank(threshold))
            .unwrap_or(false)
    });

    if json {
        let view = CiView {
            fail_on: threshold.as_str().to_string(),
            failed,
            findings,
        };
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        let scanned = queries.len();
        if offline {
            println!("scanned {scanned} deps (offline — no CVE lookup)");
        } else {
            println!(
                "scanned {scanned} deps, {} advisories found",
                findings.len()
            );
        }
        for f in &findings {
            let kev = if f.in_kev { " [KEV]" } else { "" };
            let epss = if f.epss > 0.0 {
                format!(" epss={:.0}%", f.epss * 100.0)
            } else {
                String::new()
            };
            let fixed = if f.fixed_in.is_empty() {
                String::new()
            } else {
                format!(" → fixed in {}", f.fixed_in)
            };
            println!(
                "  [{}]{kev}{epss} {}/{}@{} — {} ({}){fixed}",
                f.severity, f.ecosystem, f.name, f.version, f.advisory, f.summary
            );
        }
        println!("verdict: {}", if failed { "FAIL" } else { "pass" });
    }

    // Exit 0 clean, 1 on findings ≥ threshold, matching the Go gate.
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// JSON view of a scored analysis.
#[derive(Serialize)]
struct AnalysisView {
    verdict: String,
    score: i32,
    capabilities: Vec<String>,
    flags: Vec<FlagView>,
}

#[derive(Serialize)]
struct FlagView {
    code: String,
    detail: String,
    weight: i32,
}

fn parse_ecosystem(s: &str) -> Option<Ecosystem> {
    Some(match s.to_lowercase().as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "crates" | "cargo" => Ecosystem::Crates,
        "go" => Ecosystem::Go,
        "rubygems" | "ruby" => Ecosystem::RubyGems,
        "maven" => Ecosystem::Maven,
        "packagist" | "composer" => Ecosystem::Packagist,
        "nuget" => Ecosystem::NuGet,
        "hex" => Ecosystem::Hex,
        _ => return None,
    })
}

/// Recursively collect `(relative_path, bytes)` for regular files under
/// `root`. Bounded so a pathological tree can't exhaust memory.
fn collect_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    const MAX_FILES: usize = 20_000;
    const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if out.len() >= MAX_FILES {
                return out;
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let too_big = entry
                    .metadata()
                    .map(|m| m.len() > MAX_FILE_BYTES)
                    .unwrap_or(true);
                if too_big {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path) {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned();
                    out.push((rel, bytes));
                }
            }
        }
    }
    out
}

/// True when `rel`'s extension has a compiled-in AST scanner.
fn ext_has_scanner(
    rel: &str,
    scanners: &HashMap<String, Option<Arc<dyn LanguageScanner>>>,
) -> bool {
    rel.rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .and_then(|ext| scanners.get(&ext))
        .map(|s| s.is_some())
        .unwrap_or(false)
}

fn run_analyze(dir: &str, name: Option<&str>, ecosystem: &str, json: bool) -> ExitCode {
    let root = Path::new(dir);
    if !root.is_dir() {
        eprintln!("aegis: not a directory: {dir}");
        return ExitCode::from(2);
    }
    let Some(eco) = parse_ecosystem(ecosystem) else {
        eprintln!("aegis: unknown ecosystem: {ecosystem}");
        return ExitCode::from(2);
    };
    let pkg_name = name
        .map(String::from)
        .or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();

    let files = collect_files(root);

    // AST pass over source files — PARALLEL across all cores (rayon).
    // Compile one scanner per distinct extension present, share it read-only
    // across threads, scan every file concurrently, then merge results.
    let mut scanners: HashMap<String, Option<Arc<dyn LanguageScanner>>> = HashMap::new();
    for (rel, _) in &files {
        if let Some(ext) = rel.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()) {
            scanners
                .entry(ext)
                .or_insert_with(|| scanner_for(rel).map(Arc::from));
        }
    }
    let source_bytes: i64 = files
        .par_iter()
        .filter(|(rel, _)| ext_has_scanner(rel, &scanners))
        .map(|(_, bytes)| bytes.len() as i64)
        .sum();
    let findings = files
        .par_iter()
        .map(|(rel, bytes)| {
            let mut f = Findings::new(false);
            if let Some(ext) = rel.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()) {
                if let Some(Some(scanner)) = scanners.get(&ext) {
                    scanner.analyze_file(rel, bytes, &mut f);
                }
            }
            f
        })
        .reduce(
            || Findings::new(false),
            |mut a, b| {
                a.merge(b);
                a
            },
        );

    // Heuristics pass over the whole file set.
    let mut normalized = NormalizedPackage::new(&pkg_name, eco);
    for (rel, bytes) in &files {
        normalized = normalized.with_file(rel.clone(), bytes.clone());
    }
    let heuristic_caps = run_heuristics(&normalized);

    // Combine capabilities → fingerprint → risk verdict.
    let mut caps = findings.capabilities();
    caps.extend(heuristic_caps);
    let fp = Fingerprint {
        analyzed: true,
        capabilities: CapabilitySet::new(caps),
        env_reads: findings.env_reads().to_vec(),
        source_size_bytes: source_bytes,
        ..Default::default()
    };
    let assessment = risk_score(Some(&fp));
    let v = verdict(&assessment, &RiskAssessment::default());

    if json {
        let view = AnalysisView {
            verdict: v.name().to_string(),
            score: assessment.score,
            capabilities: fp
                .capabilities
                .iter()
                .map(|c| c.name().to_string())
                .collect(),
            flags: assessment
                .flags
                .iter()
                .map(|f| FlagView {
                    code: f.code.clone(),
                    detail: f.detail.clone(),
                    weight: f.weight,
                })
                .collect(),
        };
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!("package: {pkg_name} ({})", eco.as_str());
        println!("verdict: {}  (score {})", v.name(), assessment.score);
        if assessment.flags.is_empty() {
            println!("no risk signals detected");
        } else {
            println!("signals:");
            for f in &assessment.flags {
                println!("  [{:>3}] {} — {}", f.weight, f.code, f.detail);
            }
        }
    }
    ExitCode::SUCCESS
}

fn run_parse(file: &str, json: bool) -> ExitCode {
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("aegis: cannot read {file}: {e}");
            return ExitCode::from(2);
        }
    };
    let basename = Path::new(file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file);

    let deps = match parse_file(basename, &bytes, &DirectMap::new()) {
        Ok(Some(deps)) => deps,
        Ok(None) => {
            eprintln!("aegis: no parser for lockfile '{basename}'");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: failed to parse {basename}: {e}");
            return ExitCode::from(2);
        }
    };

    if json {
        let views: Vec<DepView> = deps.iter().map(DepView::from).collect();
        match serde_json::to_string_pretty(&views) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!("{} dependencies in {basename}:", deps.len());
        for d in &deps {
            let mark = if d.direct { "*" } else { " " };
            println!("  {mark} {}/{}@{}", d.ecosystem.as_str(), d.name, d.version);
        }
    }
    ExitCode::SUCCESS
}
