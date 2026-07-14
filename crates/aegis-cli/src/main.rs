//! The `aegis` CLI (Rust port). First runnable slice: parse a lockfile
//! through `aegis-lockfile` and report its dependencies. More commands
//! (enrich, ci, analyze) land as the usecase layer is ported.

use std::path::Path;
use std::process::ExitCode;

use aegis_ast::{scanner_for, Findings};
use aegis_domain::{
    risk_score, verdict, CapabilitySet, Dependency, Ecosystem, Fingerprint, RiskAssessment,
};
use aegis_heuristics::{run_heuristics, NormalizedPackage};
use aegis_lockfile::{parse_file, DirectMap};
use clap::{Parser, Subcommand};
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
        Command::Analyze {
            dir,
            name,
            ecosystem,
            json,
        } => run_analyze(&dir, name.as_deref(), &ecosystem, json),
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

    // AST pass over source files.
    let mut findings = Findings::new(false);
    let mut source_bytes: i64 = 0;
    for (rel, bytes) in &files {
        if let Some(scanner) = scanner_for(rel) {
            source_bytes += bytes.len() as i64;
            scanner.analyze_file(rel, bytes, &mut findings);
        }
    }

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
