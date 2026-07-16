//! The `aegis` CLI (Rust port). First runnable slice: parse a lockfile
//! through `aegis-lockfile` and report its dependencies. More commands
//! (enrich, ci, analyze) land as the usecase layer is ported.

mod commands;
mod enrich;
mod scan;
mod util;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::{
    run_allowlist, run_analyze, run_ci, run_config, run_explain, run_fix, run_image, run_parse,
    run_sbom,
};

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
        /// Emit SARIF 2.1.0 (for GitHub Code Scanning). Overrides --json.
        #[arg(long)]
        sarif: bool,
    },
    /// Run a config (aegis.toml) of scan tasks — independent tasks run
    /// in parallel; each task's source scan also fans out across cores.
    Run {
        /// Path to the config file.
        #[arg(default_value = "aegis.toml")]
        config: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Suggest version bumps that resolve known CVEs in a lockfile.
    Fix {
        /// Path to the lockfile.
        file: String,
        /// Skip the network CVE lookup (offline / air-gapped).
        #[arg(long)]
        offline: bool,
        /// Emit only the upgrade shell commands (safe to pipe to sh).
        #[arg(long)]
        script: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the built-in capability-suppression allowlist rules.
    Allowlist {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain the risk model: capabilities, their meaning, and score weight.
    Explain {
        /// A capability slug (e.g. "shell-spawn"); omit to list them all.
        capability: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan an OCI / `docker save` image tarball for risky files.
    Image {
        /// Path to the image tarball (docker save output or OCI layout).
        file: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate an SBOM (JSON) from a lockfile.
    Sbom {
        /// Path to the lockfile (e.g. package-lock.json, Cargo.lock).
        file: String,
        /// SBOM format: cyclonedx (default) or spdx.
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        /// Root component / project name for the BOM.
        #[arg(long)]
        project: Option<String>,
        /// urn:uuid serial number for the BOM (omitted when absent).
        #[arg(long)]
        serial: Option<String>,
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
        /// Also run network maintainer-metadata checks (npm packument:
        /// hijack-risk / yanked-version / maintainer-handover). Off by default
        /// so `analyze` stays offline unless asked.
        #[arg(long)]
        online: bool,
        /// Emit machine-readable JSON instead of a text summary.
        #[arg(long)]
        json: bool,
    },
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
            sarif,
        } => run_ci(&file, &fail_on, offline, json, sarif),
        Command::Run { config, json } => run_config(&config, json),
        Command::Allowlist { json } => run_allowlist(json),
        Command::Explain { capability, json } => run_explain(capability.as_deref(), json),
        Command::Image { file, json } => run_image(&file, json),
        Command::Fix {
            file,
            offline,
            script,
            json,
        } => run_fix(&file, offline, script, json),
        Command::Sbom {
            file,
            format,
            project,
            serial,
        } => run_sbom(&file, &format, project.as_deref(), serial.as_deref()),
        Command::Analyze {
            dir,
            name,
            ecosystem,
            online,
            json,
        } => run_analyze(&dir, name.as_deref(), &ecosystem, online, json),
    }
}
