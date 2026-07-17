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
    run_actions, run_allowlist, run_analyze, run_ci, run_config, run_explain, run_fix, run_hook,
    run_image, run_parse, run_reach, run_sbom, run_snapshot,
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
        /// Emit aggregate SARIF 2.1.0 across all tasks. Overrides --json.
        #[arg(long)]
        sarif: bool,
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
    /// Check whether a dependency is imported (reachable) in a project's JS/TS
    /// source — the signal that downgrades risk for unused dependencies.
    Reach {
        /// Project source directory.
        dir: String,
        /// Dependency key to look up (e.g. "lodash", "@scope/pkg").
        package: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print (or install) a git pre-commit hook that scans staged lockfiles.
    Hook {
        /// Write the hook to .git/hooks/pre-commit (and chmod +x) instead of
        /// printing it to stdout.
        #[arg(long)]
        install: bool,
    },
    /// Print a GitHub Actions workflow that runs `aegis ci` on every push.
    Actions {},
    /// Capture a package's capability fingerprint, or diff it against a
    /// baseline to detect behavioral drift between versions (takeover signal).
    Snapshot {
        /// Package source directory to fingerprint.
        dir: String,
        /// Ecosystem for heuristics.
        #[arg(long, default_value = "npm")]
        ecosystem: String,
        /// Write the fingerprint JSON to this file (else print it).
        #[arg(long)]
        out: Option<String>,
        /// Compare against this baseline fingerprint; exit 1 if new risky
        /// capabilities appeared.
        #[arg(long)]
        baseline: Option<String>,
    },
    /// Explain the risk model: capabilities, their meaning, and score weight.
    Explain {
        /// A capability slug (e.g. "shell-spawn"); omit to list them all.
        capability: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan an OCI image for risky files — from a local tarball or pulled by
    /// reference from a registry.
    Image {
        /// Path to a `docker save` / OCI-layout image tarball.
        file: Option<String>,
        /// Pull and scan a registry image by reference (e.g. `alpine:latest`,
        /// `ghcr.io/owner/repo:1.2`) instead of reading a local file.
        #[arg(long = "ref")]
        reference: Option<String>,
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
        /// Emit SARIF 2.1.0 (for GitHub Code Scanning). Overrides --json.
        #[arg(long)]
        sarif: bool,
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
        Command::Run {
            config,
            json,
            sarif,
        } => run_config(&config, json, sarif),
        Command::Allowlist { json } => run_allowlist(json),
        Command::Explain { capability, json } => run_explain(capability.as_deref(), json),
        Command::Reach { dir, package, json } => run_reach(&dir, &package, json),
        Command::Hook { install } => run_hook(install),
        Command::Actions {} => run_actions(),
        Command::Snapshot {
            dir,
            ecosystem,
            out,
            baseline,
        } => run_snapshot(&dir, &ecosystem, out.as_deref(), baseline.as_deref()),
        Command::Image {
            file,
            reference,
            json,
        } => run_image(file.as_deref(), reference.as_deref(), json),
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
            sarif,
        } => run_analyze(&dir, name.as_deref(), &ecosystem, online, json, sarif),
    }
}
