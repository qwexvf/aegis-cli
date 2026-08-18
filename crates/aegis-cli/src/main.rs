//! The `aegis` CLI (Rust port). First runnable slice: parse a lockfile
//! through `aegis-lockfile` and report its dependencies. More commands
//! (enrich, ci, analyze) land as the usecase layer is ported.

mod allowlist;
mod audit;
mod aur;
mod cache;
mod commands;
mod dash;
mod doctor;
mod enrich;
mod hook;
mod scan;
mod snapshot;
mod util;
mod workflow;

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use commands::{
    run_actions, run_allowlist, run_analyze, run_ci, run_config, run_explain, run_fix, run_image,
    run_parse, run_reach, run_sbom,
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
    /// CI gate: enrich each dep (fetch + scan → verdict) + advisories, fail on
    /// any dep whose verdict meets the threshold.
    Ci {
        /// Path to the lockfile.
        file: String,
        /// Verdict threshold to fail on: safe, review, prompt, block.
        #[arg(long, default_value = "block")]
        fail_on: String,
        /// Skip all network (no enrich, no advisory lookup) — offline gate.
        #[arg(long)]
        offline: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Emit SARIF 2.1.0 (for GitHub Code Scanning). Overrides --json.
        #[arg(long)]
        sarif: bool,
        /// Live terminal dashboard while the scan runs.
        #[arg(long)]
        dash: bool,
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
        /// Live terminal dashboard while the scan runs.
        #[arg(long)]
        dash: bool,
    },
    /// Replay a recorded run log in the terminal dashboard.
    Dash {
        /// Run log to replay: a file path or "latest".
        #[arg(long, default_value = "latest")]
        replay: String,
        /// Playback speed multiplier (e.g. 10 = 10x faster).
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        /// Jump straight to the final state instead of playing back.
        #[arg(long)]
        instant: bool,
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
    /// Manage capability suppressions. Two writable scopes: `user`
    /// ($XDG_CONFIG_HOME/aegis/allowlist.toml) and `project` (aegis.toml).
    Allowlist {
        #[command(subcommand)]
        sub: Option<AllowlistSub>,
        /// Emit machine-readable JSON. With no subcommand, dumps the builtin
        /// rules — kept for compatibility with the previous behaviour.
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
        /// Check whether this specific symbol/function of the package is used
        /// (e.g. an advisory's affected function). Exit 0 if used, 1 if not.
        #[arg(long)]
        function: Option<String>,
        /// With --function: also report functions that reach the symbol
        /// transitively through the call graph (cross-file, name-based).
        #[arg(long)]
        transitive: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print, install, or remove a git pre-commit hook that scans staged
    /// lockfiles. Detects lefthook and husky before falling back to
    /// .git/hooks, and brackets its entry in managed markers so it never
    /// clobbers a hook you already have.
    Hook {
        /// Write the step into the project's hook config.
        #[arg(long)]
        install: bool,
        /// Remove the aegis step, leaving the rest of the hook intact.
        #[arg(long, conflicts_with = "install")]
        uninstall: bool,
    },
    /// Print a GitHub Actions workflow that runs `aegis ci` on every push,
    /// or with `scan`, inspect existing workflows for risk.
    Actions {
        #[command(subcommand)]
        sub: Option<ActionsSub>,
    },
    /// Inspect the local audit log — an append-only record of what was
    /// scanned and what the verdict was.
    Audit {
        #[command(subcommand)]
        sub: AuditSub,
    },
    /// Inspect or clear the on-disk advisory caches (CISA KEV, OSV documents).
    Cache {
        #[command(subcommand)]
        sub: CacheSub,
    },
    /// Check that the environment can run a scan: cache writability,
    /// allowlist validity, advisory-feed reachability, git, GITHUB_TOKEN.
    /// Exits 1 on any failure; warnings alone exit 0.
    Doctor {
        /// Skip the network reachability check.
        #[arg(long)]
        offline: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a shell completion script.
    ///
    ///   bash: source <(aegis completion bash)
    ///   zsh:  aegis completion zsh > "${fpath[1]}/_aegis"
    ///   fish: aegis completion fish > ~/.config/fish/completions/aegis.fish
    Completion {
        /// Shell to generate for.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Snapshot lifecycle: save / show / diff / enrich / verify / rescan plus
    /// `capture` (the Rust-specific single-package fingerprint mode). Run
    /// `aegis snapshot help` for the per-subcommand detail.
    Snapshot {
        #[command(subcommand)]
        sub: SnapshotSub,
    },
    /// Scan an AUR package directory's PKGBUILD and .install hooks for
    /// malware-delivery patterns — the install gate for paru/yay.
    Aur {
        #[command(subcommand)]
        sub: AurSub,
    },
    /// Explain the risk model: capabilities, their meaning, and score weight.
    Explain {
        /// A capability slug (e.g. "shell-spawn") for the risk-model doc, OR a
        /// package spec "name@version" (e.g. "lodash@4.17.4") to fetch + scan
        /// that published package and explain its capabilities. Omit for the
        /// full capability catalog.
        capability: Option<String>,
        /// Ecosystem for a package spec (default: npm). Ignored for the doc.
        #[arg(long, default_value = "npm")]
        ecosystem: String,
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
        /// Registry username for a private pull (else $AEGIS_REGISTRY_USER).
        #[arg(long)]
        username: Option<String>,
        /// Registry password/token for a private pull (else
        /// $AEGIS_REGISTRY_PASS).
        #[arg(long)]
        password: Option<String>,
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
        /// Resolve each dependency's SPDX license from its registry and
        /// populate the SBOM license fields (network). Off by default so
        /// `sbom` stays offline (licenses render as NOASSERTION / omitted).
        #[arg(long)]
        online: bool,
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
        /// Path to a TOML file of `[[allow]]` capability-suppression rules,
        /// merged on top of the builtin allowlist.
        #[arg(long)]
        allowlist: Option<String>,
        /// Emit machine-readable JSON instead of a text summary.
        #[arg(long)]
        json: bool,
        /// Emit SARIF 2.1.0 (for GitHub Code Scanning). Overrides --json.
        #[arg(long)]
        sarif: bool,
    },
}

/// `aegis actions` subcommands.
#[derive(Subcommand)]
enum ActionsSub {
    /// Scan workflow files for unpinned action refs, script injection,
    /// over-broad permissions, and suspicious run steps.
    Scan {
        /// Directory of workflow files. Defaults to .github/workflows.
        dir: Option<String>,
        /// Exit 1 when a finding reaches this severity.
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `aegis allowlist` subcommands.
#[derive(Subcommand)]
enum AllowlistSub {
    /// Show every rule: builtin, user, and project.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Add a suppression. `--reason` is required — an unexplained
    /// suppression is indistinguishable from a mistake later.
    Add {
        /// Package name, or "*" for every package in the ecosystem.
        name: String,
        #[arg(long, default_value = "npm")]
        ecosystem: String,
        /// Capability slug to suppress. Omit for any.
        #[arg(long)]
        capability: Option<String>,
        /// Semver range. Omit for any version.
        #[arg(long, default_value = "")]
        version: String,
        /// Why this is acceptable. Required.
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long, default_value = "user")]
        scope: String,
    },
    /// Remove suppressions matching a package (and optionally a capability).
    Remove {
        name: String,
        #[arg(long, default_value = "npm")]
        ecosystem: String,
        /// Only remove the rule for this capability.
        #[arg(long)]
        capability: Option<String>,
        #[arg(long, default_value = "user")]
        scope: String,
    },
    /// Show which rules suppress a given package.
    Test {
        /// `<ecosystem>/<name>@<version>`, e.g. `npm/lodash@4.17.21`.
        spec: String,
    },
    /// Validate the user and project allowlist files. Exits 1 on a problem.
    Verify,
}

/// `aegis audit` subcommands.
#[derive(Subcommand)]
enum AuditSub {
    /// Show the most recent entries, oldest first.
    Tail {
        /// How many to show. 0 shows everything.
        #[arg(short = 'n', long, default_value_t = 20)]
        count: usize,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `aegis cache` subcommands.
#[derive(Subcommand)]
enum CacheSub {
    /// Show each cache pool: entry count, size, how many are past their TTL.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Delete cached entries. Safe — they are refetched on demand.
    Clear {
        /// Only this pool (`kev` or `osv`). Omit to clear everything.
        pool: Option<String>,
    },
}

/// `aegis aur` subcommands — the PKGBUILD install gate.
#[derive(Subcommand)]
enum AurSub {
    /// Scan a package directory containing a PKGBUILD (and any .install
    /// hooks). Exits 1 on a block verdict, 0 otherwise. A gate driving this
    /// programmatically must branch on the per-package verdict in --json,
    /// not on the exit code.
    Scan {
        /// Directory holding the PKGBUILD (e.g. ~/.cache/paru/clone/<pkg>).
        dir: String,
        /// Emit the machine-readable report paru consumes.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a BUILT package (.pkg.tar.zst) before `pacman -U` installs it:
    /// pacman hooks, setuid bits, sudoers drop-ins, ld.so.preload, files
    /// outside the managed prefixes. Sees what the build produced, which the
    /// PKGBUILD text cannot show.
    Inspect {
        /// Path to the built package.
        file: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan a whole transaction from a JSON payload on stdin — one process
    /// per transaction rather than one per package. Exits 0 whenever the
    /// scan succeeded; read the per-package verdicts from the report.
    Gate,
}

/// `aegis snapshot` subcommands — the `aegis.lock` lifecycle.
#[derive(Subcommand)]
enum SnapshotSub {
    /// Scan the project lockfile and write a bare `aegis.lock` (no enrichment,
    /// no network). The save is fast — fingerprints arrive via `enrich`.
    Save {
        /// Project directory. Defaults to the current working directory.
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Render the saved snapshot. By default direct deps only; `--all`
    /// includes transitives, `--used-only` hides deps confirmed unused.
    Show {
        /// Project directory.
        #[arg(default_value = ".")]
        dir: String,
        /// Include transitive deps, not just direct.
        #[arg(long)]
        all: bool,
        /// Hide deps confirmed unused (Unknown rows remain visible).
        #[arg(long)]
        used_only: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Diff two snapshots: zero args = saved `aegis.lock` vs a fresh re-scan
    /// of the project lockfile; two file paths = explicit two-file diff.
    /// Per-entry verdicts (verdict=safe/review/prompt/block) are advisory.
    Diff {
        /// Project directory (used when neither `a` nor `b` given).
        #[arg(default_value = ".")]
        dir: String,
        /// First snapshot file path (two-file mode).
        #[arg(name = "A")]
        a: Option<String>,
        /// Second snapshot file path (two-file mode).
        #[arg(name = "B")]
        b: Option<String>,
    },
    /// Enrich the saved snapshot in place: fetch each dep's published source,
    /// AST + heuristics scan it, fold in advisories (OSV+GHSA+EPSS+KEV), and
    /// classify reachability. Idempotent — re-runs only process newly-saved
    /// deps. Needs network.
    Enrich {
        /// Project directory.
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Lint the saved snapshot for loadability + schema version. Exits 0 even
    /// on a schema mismatch (informational; re-run `snapshot save` to update).
    Verify {
        /// Project directory.
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Re-query the advisory feed for every saved dep; exit 1 when any new
    /// advisory appeared (the cron-page contract). Saves the updated snapshot.
    Rescan {
        /// Project directory.
        #[arg(default_value = ".")]
        dir: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// (Rust extension) Capture a single package's capability fingerprint,
    /// or diff it against a `--baseline` to detect behavioral drift between
    /// versions (the maintainer-takeover signal). Exits 1 when a new risky
    /// capability appears. This is the original `snapshot <dir>` behavior
    /// before the verb grew the `aegis.lock` lifecycle subcommands.
    Capture {
        /// Package source directory to fingerprint.
        dir: String,
        /// Ecosystem for heuristics (default npm).
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
            dash,
        } => run_ci(&file, &fail_on, offline, json, sarif, dash),
        Command::Run {
            config,
            json,
            sarif,
            dash,
        } => run_config(&config, json, sarif, dash),
        Command::Dash {
            replay,
            speed,
            instant,
        } => dash::run_dash(&replay, speed, instant),
        Command::Allowlist { sub, json } => match sub {
            None => run_allowlist(json),
            Some(AllowlistSub::List { json }) => allowlist::run_list(json),
            Some(AllowlistSub::Add {
                name,
                ecosystem,
                capability,
                version,
                reason,
                scope,
            }) => allowlist::run_add(
                &name,
                &ecosystem,
                capability.as_deref(),
                &version,
                &reason,
                &scope,
            ),
            Some(AllowlistSub::Remove {
                name,
                ecosystem,
                capability,
                scope,
            }) => allowlist::run_remove(&name, &ecosystem, capability.as_deref(), &scope),
            Some(AllowlistSub::Test { spec }) => allowlist::run_test(&spec),
            Some(AllowlistSub::Verify) => allowlist::run_verify(),
        },
        Command::Explain {
            capability,
            ecosystem,
            json,
        } => run_explain(capability.as_deref(), &ecosystem, json),
        Command::Reach {
            dir,
            package,
            function,
            transitive,
            json,
        } => run_reach(&dir, &package, function.as_deref(), transitive, json),
        Command::Hook { install, uninstall } => hook::run_hook(install, uninstall),
        Command::Actions { sub } => match sub {
            None => run_actions(),
            Some(ActionsSub::Scan { dir, fail_on, json }) => {
                workflow::run_actions_scan(dir.as_deref(), &fail_on, json)
            }
        },
        Command::Snapshot { sub } => match sub {
            SnapshotSub::Save { dir } => snapshot::run_snapshot_save(&dir),
            SnapshotSub::Show {
                dir,
                all,
                used_only,
                json,
            } => snapshot::run_snapshot_show(&dir, all, used_only, json),
            SnapshotSub::Diff { dir, a, b } => {
                snapshot::run_snapshot_diff(&dir, a.as_deref(), b.as_deref())
            }
            SnapshotSub::Enrich { dir } => snapshot::run_snapshot_enrich(&dir),
            SnapshotSub::Verify { dir } => snapshot::run_snapshot_verify(&dir),
            SnapshotSub::Rescan { dir, json } => snapshot::run_snapshot_rescan(&dir, json),
            SnapshotSub::Capture {
                dir,
                ecosystem,
                out,
                baseline,
            } => snapshot::run_snapshot_capture(
                &dir,
                &ecosystem,
                out.as_deref(),
                baseline.as_deref(),
            ),
        },
        Command::Doctor { offline, json } => doctor::run_doctor(offline, json),
        Command::Audit { sub } => match sub {
            AuditSub::Tail { count, json } => audit::run_audit_tail(count, json),
        },
        Command::Cache { sub } => match sub {
            CacheSub::List { json } => cache::run_cache_list(json),
            CacheSub::Clear { pool } => cache::run_cache_clear(pool.as_deref()),
        },
        Command::Completion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            ExitCode::SUCCESS
        }
        Command::Aur { sub } => match sub {
            AurSub::Scan { dir, json } => aur::run_aur_scan(&dir, json),
            AurSub::Gate => aur::run_aur_gate(),
            AurSub::Inspect { file, json } => aur::run_pkg_inspect(&file, json),
        },
        Command::Image {
            file,
            reference,
            username,
            password,
            json,
        } => run_image(
            file.as_deref(),
            reference.as_deref(),
            username.as_deref(),
            password.as_deref(),
            json,
        ),
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
            online,
        } => run_sbom(
            &file,
            &format,
            project.as_deref(),
            serial.as_deref(),
            online,
        ),
        Command::Analyze {
            dir,
            name,
            ecosystem,
            online,
            allowlist,
            json,
            sarif,
        } => run_analyze(
            &dir,
            name.as_deref(),
            &ecosystem,
            online,
            allowlist.as_deref(),
            json,
            sarif,
        ),
    }
}
