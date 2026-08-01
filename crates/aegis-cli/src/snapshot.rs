//! The `aegis.lock` snapshot lifecycle — a port of Go's `snapshot` subcommand
//! tree (`internal/interface/cli/snapshot_command.go` +
//! `internal/usecase/snapshot.go` + `internal/infra/locksnap/store.go`).
//!
//! The `snapshot` verb is structured as a subcommand tree:
//!
//! ```text
//! aegis snapshot save      — project lockfile → bare aegis.lock (no enrichment)
//! aegis snapshot show      — render the saved snapshot (--all/--used-only/--json)
//! aegis snapshot diff      — saved-vs-live or two-file Added/Removed/Upgraded + verdict per entry
//! aegis snapshot enrich    — per-dep AST scan + advisories + reachability, persisted idempotently
//! aegis snapshot verify    — loadability + schema-version linter
//! aegis snapshot rescan    — re-query the advisory feed for new CVEs; exit 1 on any
//! aegis snapshot capture   — (Rust extension) single-package capability fingerprint, with --baseline drift
//! ```
//!
//! `capture` is the Rust-specific single-package behavior the verb used to be;
//! it is preserved under a subcommand so existing scripts that ran
//! `aegis snapshot <dir> [--baseline]` keep working as
//! `aegis snapshot capture <dir> [--baseline]`.
//!
//! ## On-disk format (deliberate divergence from Go)
//!
//! Go writes `aegis.lock` as zstd-compressed JSON (the local-cache-heavy dev
//! workflow re-reads it constantly). The Rust port is CI-first and git-flow
//! oriented — a plain pretty-JSON `aegis.lock` is git-diffable and audit-
//! friendly, exactly what a project committing `aegis.lock` next to
//! `Cargo.lock` wants. The schema mirrors Go's `domain.Snapshot` field-for-
//! field; only the outer compression differs. A Go-written zstd `aegis.lock`
//! will fail to load here with a clear "re-run `aegis snapshot save`" message.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aegis_domain::{
    apply_allowlist, builtin_allow_rules, diff_snapshots, downgrade_verdict, drift_score,
    patch_version_drift_flag, provenance_risk_flag, risk_score, verdict, verdict_for_advisories,
    Advisory, AdvisoryQuery, Capability, CapabilitySet, Dependency, Ecosystem, Fingerprint,
    HookPhase, InstallHook, Reachability, RiskFlag, Snapshot as DomainSnapshot, VerdictKind,
    SNAPSHOT_SCHEMA_VERSION,
};
use aegis_lockfile::{builtin_parsers, parse_file, DirectMap};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::enrich::advisories_by_key;
use crate::scan::{collect_files, fingerprint_source, project_reachability, reachability_eligible};
use crate::util::parse_ecosystem;

/// Canonical on-disk filename — matches Go's `LockfileName`.
pub(crate) const LOCKFILE_NAME: &str = "aegis.lock";

/// One entry in the persisted `aegis.lock` file. Mirrors Go's
/// `dependencyDTO` (`internal/infra/locksnap/store.go:142-162`).
#[derive(Serialize, Deserialize, Clone)]
struct DepDto {
    ecosystem: String,
    name: String,
    version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    integrity: String,
    #[serde(default, skip_serializing_if = "is_false")]
    direct: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    /// `None` = never scanned; `Some` = AST+heuristics pass has run. Mirrors
    /// Go's `*fingerprintDTO`. Null in JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fp: Option<FingerprintDto>,
    /// `None` = no advisory lookup has run; `Some([])` = looked-up-empty.
    /// The Go nil-vs-[] idempotency contract: skip enriching deps with Some(_).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    advisories: Option<Vec<AdvisoryDto>>,
    /// `"used"` / `"unused"` / `""` (unknown). Empty by default.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    reach: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    license: String,
    #[serde(default, skip_serializing_if = "is_false")]
    deprecated: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    deprecated_reason: String,
    /// "missing" / "attested" / "error" / "" (unqueried).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    provenance_status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    provenance_source_uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    provenance_commit: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct FingerprintDto {
    #[serde(default, skip_serializing_if = "is_false")]
    analyzed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hooks: Vec<HookDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    env_reads: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    source_size_bytes: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct HookDto {
    phase: String,
    source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sha256: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct AdvisoryDto {
    id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
    severity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    summary: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fixed_in: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    affected_functions: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    epss: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    epss_percentile: f64,
    #[serde(default, skip_serializing_if = "is_false")]
    in_kev: bool,
}

/// Top-level `aegis.lock` JSON. Mirrors Go's `fileSchema`.
#[derive(Serialize, Deserialize)]
struct FileSchema {
    schema_version: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    aegis_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    project: String,
    #[serde(default)]
    deps: Vec<DepDto>,
}

// ---------- helpers for serde skip_if predicates ----------

fn is_false(b: &bool) -> bool {
    !b
}
fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}
fn is_zero_f64(n: &f64) -> bool {
    *n == 0.0
}

// ---------- domain <-> DTO conversions ----------

fn parse_eco_dto(s: &str) -> Option<Ecosystem> {
    parse_ecosystem(s)
}

fn eco_to_dto(e: Ecosystem) -> &'static str {
    e.as_str()
}

fn reach_to_dto(r: Reachability) -> &'static str {
    match r {
        Reachability::Used => "used",
        Reachability::Unused => "unused",
        Reachability::Unknown => "",
    }
}

fn reach_from_dto(s: &str) -> Reachability {
    match s {
        "used" => Reachability::Used,
        "unused" => Reachability::Unused,
        _ => Reachability::Unknown,
    }
}

fn hook_phase_to_dto(p: HookPhase) -> &'static str {
    p.name()
}

fn hook_phase_from_dto(s: &str) -> HookPhase {
    match s {
        "pre-install" => HookPhase::PreInstall,
        "build" => HookPhase::Build,
        _ => HookPhase::PostInstall,
    }
}

fn sev_to_dto(s: aegis_domain::Severity) -> &'static str {
    s.as_str()
}

fn sev_from_dto(s: &str) -> aegis_domain::Severity {
    use aegis_domain::Severity;
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn fp_to_dto(fp: &Fingerprint) -> FingerprintDto {
    FingerprintDto {
        analyzed: fp.analyzed,
        capabilities: fp
            .capabilities
            .iter()
            .map(|c| c.name().to_string())
            .collect(),
        hooks: fp
            .hooks
            .iter()
            .map(|h| HookDto {
                phase: hook_phase_to_dto(h.phase).to_string(),
                source: h.source.clone(),
                sha256: h.sha256.clone(),
            })
            .collect(),
        env_reads: fp.env_reads.clone(),
        source_size_bytes: fp.source_size_bytes,
    }
}

fn fp_from_dto(dto: &FingerprintDto) -> Fingerprint {
    let caps: Vec<Capability> = dto
        .capabilities
        .iter()
        .filter_map(|c| Capability::from_name(c))
        .collect();
    let hooks: Vec<InstallHook> = dto
        .hooks
        .iter()
        .map(|h| InstallHook {
            phase: hook_phase_from_dto(&h.phase),
            source: h.source.clone(),
            sha256: h.sha256.clone(),
        })
        .collect();
    Fingerprint {
        analyzed: dto.analyzed,
        capabilities: CapabilitySet::new(caps),
        env_reads: dto.env_reads.clone(),
        source_size_bytes: dto.source_size_bytes,
        hooks,
    }
}

fn adv_to_dto(a: &Advisory) -> AdvisoryDto {
    AdvisoryDto {
        id: a.id.clone(),
        aliases: a.aliases.clone(),
        severity: sev_to_dto(a.severity).to_string(),
        summary: a.summary.clone(),
        url: a.url.clone(),
        source: a.source.clone(),
        fixed_in: a.fixed_in.clone(),
        affected_functions: a.affected_functions.clone(),
        epss: a.epss,
        epss_percentile: a.epss_percentile,
        in_kev: a.in_kev,
    }
}

fn adv_from_dto(a: &AdvisoryDto) -> Advisory {
    Advisory {
        id: a.id.clone(),
        aliases: a.aliases.clone(),
        severity: sev_from_dto(&a.severity),
        summary: a.summary.clone(),
        url: a.url.clone(),
        source: a.source.clone(),
        fixed_in: a.fixed_in.clone(),
        affected_functions: a.affected_functions.clone(),
        epss: a.epss,
        epss_percentile: a.epss_percentile,
        in_kev: a.in_kev,
    }
}

fn dep_to_dto(d: &Dependency) -> DepDto {
    DepDto {
        ecosystem: eco_to_dto(d.ecosystem).to_string(),
        name: d.name.clone(),
        version: d.version.clone(),
        integrity: d.integrity.clone(),
        direct: d.direct,
        depends_on: d.depends_on.clone(),
        fp: d.fingerprint.as_ref().map(fp_to_dto),
        advisories: d
            .advisories
            .as_ref()
            .map(|v| v.iter().map(adv_to_dto).collect()),
        reach: reach_to_dto(d.reachability).to_string(),
        symbols: d.used_symbols.clone(),
        license: d.license.clone(),
        deprecated: d.deprecated,
        deprecated_reason: d.deprecated_reason.clone(),
        provenance_status: d.provenance_status.clone(),
        provenance_source_uri: d.provenance_source_uri.clone(),
        provenance_commit: d.provenance_commit.clone(),
    }
}

fn dep_from_dto(d: &DepDto) -> Dependency {
    let ecosystem = parse_eco_dto(&d.ecosystem).unwrap_or(Ecosystem::Npm);
    Dependency {
        ecosystem,
        name: d.name.clone(),
        version: d.version.clone(),
        integrity: d.integrity.clone(),
        direct: d.direct,
        depends_on: d.depends_on.clone(),
        fingerprint: d.fp.as_ref().map(fp_from_dto),
        advisories: d
            .advisories
            .as_ref()
            .map(|v| v.iter().map(adv_from_dto).collect()),
        reachability: reach_from_dto(&d.reach),
        used_symbols: d.symbols.clone(),
        license: d.license.clone(),
        deprecated: d.deprecated,
        deprecated_reason: d.deprecated_reason.clone(),
        provenance_status: d.provenance_status.clone(),
        provenance_source_uri: d.provenance_source_uri.clone(),
        provenance_commit: d.provenance_commit.clone(),
        // Default for fields the older Go schema (`source`) carried separately.
        // Rust's `Dependency` doesn't track source-location (lockfile vs manifest)
        // — the discoverer passes deps in, so the snapshot doesn't need it.
    }
}

fn snapshot_to_file(snap: &DomainSnapshot) -> FileSchema {
    FileSchema {
        schema_version: snap.schema_version,
        created_at: snap.created_at.clone(),
        aegis_version: snap.aegis_version.clone(),
        project: snap.project.clone(),
        deps: snap.deps.iter().map(dep_to_dto).collect(),
    }
}

fn snapshot_from_file(f: &FileSchema) -> DomainSnapshot {
    DomainSnapshot {
        schema_version: f.schema_version,
        created_at: f.created_at.clone(),
        aegis_version: f.aegis_version.clone(),
        project: f.project.clone(),
        deps: f.deps.iter().map(dep_from_dto).collect(),
    }
}

// ---------- SnapshotStore: atomic read/write of aegis.lock ----------

/// Resolve the canonical `aegis.lock` path: `<project_dir>/aegis.lock`. When
/// `project_dir` is empty, the current process working directory is used.
fn lockfile_path(project_dir: &str) -> PathBuf {
    let dir = if project_dir.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(project_dir)
    };
    dir.join(LOCKFILE_NAME)
}

/// Write `aegis.lock` atomically (temp file + rename) to `path`. Pretty-JSON
/// encoded so the file is git-diffable.
fn save_snapshot(path: &Path, snap: &DomainSnapshot) -> Result<(), String> {
    let file = snapshot_to_file(snap);
    let json =
        serde_json::to_string_pretty(&file).map_err(|e| format!("encode aegis.lock: {e}"))?;
    let tmp = path.with_extension("lock.tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("open {}: {e}", tmp.display()))?;
    f.write_all(json.as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    f.sync_all()
        .map_err(|e| format!("sync {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename → {}: {e}", path.display()))?;
    Ok(())
}

/// Load `aegis.lock`. Tolerates a missing file (returns None) but errors on
/// unreadable / unparseable / compressed (Go-written) snapshots.
fn load_snapshot_file(path: &Path) -> Result<Option<DomainSnapshot>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    // Compressed snapshots from the Go tooling start with the zstd magic
    // (0x28 0xB5 0x2F 0xFD). Detect that up front with a clear message.
    if bytes.len() >= 4 && bytes[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Err(format!(
            "{}: appears compressed (Go-written zstd). Rust writes plain JSON; re-run `aegis snapshot save` to capture a Rust-native snapshot.",
            path.display()
        ));
    }
    let file: FileSchema =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok(Some(snapshot_from_file(&file)))
}

/// Load the canonical `aegis.lock` for `project_dir`.
fn load_snapshot(project_dir: &str) -> Result<Option<DomainSnapshot>, String> {
    load_snapshot_file(&lockfile_path(project_dir))
}

// ---------- lockfile discovery ----------
//
// Go's `scanner.ScanProject(projectDir)` walks the project and parses every
// recognized lockfile, merging deps. Mirrors that here: enumerate the
// built-in parsers' filenames and parse each one found at the project root.

/// Find every recognized lockfile at `project_dir` (no recursion — matches Go
/// which reads only the project root) and collect its parsed deps.
fn scan_project(project_dir: &Path) -> Result<Vec<Dependency>, String> {
    let mut out: Vec<Dependency> = Vec::new();
    let mut seen_basename: std::collections::HashSet<String> = std::collections::HashSet::new();
    for parser in builtin_parsers() {
        let fname = parser.filename();
        // Only one parser per basename is registered (the first-match wins in
        // `parse_file`), so deduping on filename avoids double-parsing
        // (e.g. two npm parsers registered to "package-lock.json").
        if !seen_basename.insert(fname.to_string()) {
            continue;
        }
        let lockfile_path = project_dir.join(fname);
        let Ok(raw) = std::fs::read(&lockfile_path) else {
            continue;
        };
        match parse_file(fname, &raw, &DirectMap::new()) {
            Ok(Some(deps)) => out.extend(deps),
            Ok(None) => {}
            Err(e) => return Err(format!("parse {}: {e}", lockfile_path.display())),
        }
    }
    Ok(out)
}

/// Project name — the basename of `dir`, or the cwd when `dir == "."`/empty.
/// Mirrors Go's `base(cwd)` default.
fn project_name(dir: &Path) -> String {
    if dir.as_os_str().is_empty() || dir == Path::new(".") {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "project".to_string())
    } else {
        dir.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "project".to_string())
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn aegis_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------- subcommand: save ----------

/// `aegis snapshot save` — scan the lockfile(s) at the project root and write
/// a bare `aegis.lock` (no enrichment, no fingerprints, no network).
pub(crate) fn run_snapshot_save(project_dir: &str) -> ExitCode {
    let dir = if project_dir.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(project_dir)
    };
    let deps = match scan_project(&dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    if deps.is_empty() {
        println!("no lockfile found in {} — nothing to save", dir.display());
        return ExitCode::SUCCESS;
    }
    let path = lockfile_path(project_dir);
    if path.exists() {
        eprintln!("aegis: overwriting existing {}", path.display());
    }
    let snap = DomainSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        created_at: now_rfc3339(),
        aegis_version: aegis_version(),
        project: project_name(&dir),
        deps,
    };
    let dep_count = snap.len();
    if let Err(e) = save_snapshot(&path, &snap) {
        eprintln!("aegis: {e}");
        return ExitCode::from(2);
    }
    println!("saved {dep_count} deps → {}", path.display());
    ExitCode::SUCCESS
}

// ---------- subcommand: show ----------

/// `aegis snapshot show` — render the saved snapshot. By default direct deps
/// only; `--all` includes transitives. `--used-only` hides deps confirmed
/// unused (Unknown rows stay visible). `--json` emits a machine-readable
/// JSON view.
pub(crate) fn run_snapshot_show(
    project_dir: &str,
    all: bool,
    used_only: bool,
    json: bool,
) -> ExitCode {
    let snap = match load_snapshot(project_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            println!("no snapshot saved — run `aegis snapshot save` first");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    // Most lockfile parsers don't distinguish direct from transitive yet (only
    // maven + python requirements do), so a direct-only filter would render an
    // empty table for a snapshot that clearly has deps. Fall back to showing
    // everything when nothing is marked direct.
    let has_direct = snap.deps.iter().any(|d| d.direct);
    let show_all = all || !has_direct;
    let rows: Vec<&Dependency> = snap
        .deps
        .iter()
        .filter(|d| show_all || d.direct)
        .filter(|d| !used_only || d.reachability != Reachability::Unused)
        .collect();

    if json {
        let view: Vec<ShowRow> = rows.iter().map(|d| ShowRow::from(*d)).collect();
        match serde_json::to_string_pretty(&ShowReport {
            project: snap.project,
            deps: view,
        }) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }

    if rows.is_empty() {
        println!("snapshot is empty");
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<8} {:<32} {:<16} {:<7} {:<6} {:<10}",
        "ECO", "NAME", "VERSION", "DIRECT", "CAPS", "ADVISORIES"
    );
    for d in &rows {
        let caps = d
            .fingerprint
            .as_ref()
            .map(|fp| {
                if fp.capabilities.is_empty() {
                    "—".to_string()
                } else {
                    fp.capabilities.len().to_string()
                }
            })
            .unwrap_or_default();
        let advs = d
            .advisories
            .as_ref()
            .map(|v| v.len().to_string())
            .unwrap_or_default();
        let direct = if d.direct { "yes" } else { "" };
        let unused = if d.reachability == Reachability::Unused {
            " [unused]"
        } else {
            ""
        };
        println!(
            "{:<8} {:<32} {:<16} {:<7} {:<6} {:<10}{}",
            d.ecosystem.as_str(),
            truncate(&d.name, 32),
            truncate(&d.version, 16),
            direct,
            caps,
            advs,
            unused
        );
    }
    let total = snap.deps.len();
    let shown = rows.len();
    let hidden = total.saturating_sub(shown);
    if show_all {
        println!("shown {shown} of {total} deps");
    } else {
        println!("shown {shown} direct deps (--all to include {hidden} transitives)");
    }
    let removed_unused = snap
        .deps
        .iter()
        .filter(|d| (show_all || d.direct) && d.reachability == Reachability::Unused)
        .count();
    if used_only && removed_unused > 0 {
        println!("hid {removed_unused} unused deps");
    }
    ExitCode::SUCCESS
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[derive(Serialize)]
struct ShowReport {
    project: String,
    deps: Vec<ShowRow>,
}

#[derive(Serialize)]
struct ShowRow {
    ecosystem: String,
    name: String,
    version: String,
    direct: bool,
    reachability: String,
    capabilities: Vec<String>,
    advisories: usize,
    license: String,
    deprecated: bool,
}

impl From<&Dependency> for ShowRow {
    fn from(d: &Dependency) -> Self {
        ShowRow {
            ecosystem: d.ecosystem.as_str().to_string(),
            name: d.name.clone(),
            version: d.version.clone(),
            direct: d.direct,
            reachability: reach_to_dto(d.reachability).to_string(),
            capabilities: d
                .fingerprint
                .as_ref()
                .map(|fp| {
                    fp.capabilities
                        .iter()
                        .map(|c| c.name().to_string())
                        .collect()
                })
                .unwrap_or_default(),
            advisories: d.advisories.as_ref().map(|v| v.len()).unwrap_or(0),
            license: d.license.clone(),
            deprecated: d.deprecated,
        }
    }
}

// ---------- subcommand: verify ----------

/// `aegis snapshot verify` — loadability + schema-version linter. Exits 0 in
/// all non-error cases (a schema mismatch is informational, not a failure,
/// mirroring Go's behavior).
pub(crate) fn run_snapshot_verify(project_dir: &str) -> ExitCode {
    let snap = match load_snapshot(project_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            println!("no snapshot to verify");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    if snap.schema_version != SNAPSHOT_SCHEMA_VERSION {
        println!(
            "schema mismatch: file={}, current={} (re-run `aegis snapshot save`)",
            snap.schema_version, SNAPSHOT_SCHEMA_VERSION
        );
        return ExitCode::SUCCESS;
    }
    println!(
        "snapshot OK: {} deps, schema v{}, saved {}",
        snap.len(),
        snap.schema_version,
        if snap.created_at.is_empty() {
            "(unknown time)"
        } else {
            &snap.created_at
        }
    );
    ExitCode::SUCCESS
}

// ---------- subcommand: diff ----------

/// One entry in the diff report: the kind, the dep identity, the computed
/// verdict, the risk score, and the drift score (when upgrading).
#[derive(Serialize)]
struct DiffEntryView {
    kind: &'static str,
    ecosystem: String,
    name: String,
    prev_version: String,
    next_version: String,
    verdict: String,
    risk_score: i32,
    drift_score: i32,
    risk_flags: Vec<RiskFlagView>,
    drift_flags: Vec<RiskFlagView>,
}

#[derive(Serialize)]
struct RiskFlagView {
    code: String,
    detail: String,
    weight: i32,
}

impl From<&RiskFlag> for RiskFlagView {
    fn from(f: &RiskFlag) -> Self {
        RiskFlagView {
            code: f.code.clone(),
            detail: f.detail.clone(),
            weight: f.weight,
        }
    }
}

/// `aegis snapshot diff [a.lock] [b.lock]` — compares snapshots. With zero
/// args it diffs the saved `aegis.lock` against a fresh re-scan of the
/// project lockfile (carry-forward of fingerprints for unchanged versions, so
/// the diff can compare FP-old vs FP-new without re-enriching). With two
/// paths it diffs the two named files. One-arg is rejected.
pub(crate) fn run_snapshot_diff(
    project_dir: &str,
    a_path: Option<&str>,
    b_path: Option<&str>,
) -> ExitCode {
    match (a_path, b_path) {
        (Some(a), Some(b)) => run_snapshot_diff_files(a, b),
        (None, None) => run_snapshot_diff_live(project_dir),
        (Some(_), None) | (None, Some(_)) => {
            eprintln!(
                "aegis: diff requires either zero arguments (saved-vs-live) or two file paths"
            );
            ExitCode::from(2)
        }
    }
}

fn run_snapshot_diff_files(a_path: &str, b_path: &str) -> ExitCode {
    let prev = match load_snapshot_file(Path::new(a_path)) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("aegis: no snapshot at {a_path}");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let next = match load_snapshot_file(Path::new(b_path)) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("aegis: no snapshot at {b_path}");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    print_diff(&prev, &next);
    ExitCode::SUCCESS
}

fn run_snapshot_diff_live(project_dir: &str) -> ExitCode {
    let prev = match load_snapshot(project_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("aegis: no snapshot saved — run `aegis snapshot save` first");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let dir = if project_dir.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(project_dir)
    };
    let live_deps = match scan_project(&dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    // Carry fingerprints forward from `prev` to live deps whose version is
    // unchanged, so the diff can score FP-old vs FP-new without re-enriching.
    let next_deps: Vec<Dependency> =
        live_deps
            .into_iter()
            .map(|mut d| {
                if let Some(prev_dep) = prev.deps.iter().find(|p| {
                    p.ecosystem == d.ecosystem && p.name == d.name && p.version == d.version
                }) {
                    d.fingerprint = prev_dep.fingerprint.clone();
                    d.advisories = prev_dep.advisories.clone();
                    d.reachability = prev_dep.reachability;
                    d.license = prev_dep.license.clone();
                    d.deprecated = prev_dep.deprecated;
                    d.deprecated_reason = prev_dep.deprecated_reason.clone();
                    d.provenance_status = prev_dep.provenance_status.clone();
                }
                d
            })
            .collect();
    let next = DomainSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        created_at: now_rfc3339(),
        aegis_version: aegis_version(),
        project: prev.project.clone(),
        deps: next_deps,
    };
    print_diff(&prev, &next);
    ExitCode::SUCCESS
}

fn print_diff(prev: &DomainSnapshot, next: &DomainSnapshot) {
    let deltas = diff_snapshots(prev, next);
    let allow = aegis_domain::AllowSet::new(builtin_allow_rules())
        .unwrap_or_else(|_| aegis_domain::AllowSet::empty());
    let mut views: Vec<DiffEntryView> = Vec::new();
    let mut any_blocked = false;
    let mut any_prompt = false;

    for delta in &deltas {
        let view = match delta {
            aegis_domain::DepDelta::Added(d) => {
                let (v, risk, drift, rf, df) = score_diff_entry(d, None, &allow);
                if v == VerdictKind::Block {
                    any_blocked = true;
                }
                if v == VerdictKind::Prompt {
                    any_prompt = true;
                }
                DiffEntryView {
                    kind: "added",
                    ecosystem: d.ecosystem.as_str().to_string(),
                    name: d.name.clone(),
                    prev_version: String::new(),
                    next_version: d.version.clone(),
                    verdict: v.name().to_string(),
                    risk_score: risk,
                    drift_score: drift,
                    risk_flags: rf.iter().map(RiskFlagView::from).collect(),
                    drift_flags: df.iter().map(RiskFlagView::from).collect(),
                }
            }
            aegis_domain::DepDelta::Removed(d) => DiffEntryView {
                kind: "removed",
                ecosystem: d.ecosystem.as_str().to_string(),
                name: d.name.clone(),
                prev_version: d.version.clone(),
                next_version: String::new(),
                verdict: VerdictKind::Safe.name().to_string(),
                risk_score: 0,
                drift_score: 0,
                risk_flags: Vec::new(),
                drift_flags: Vec::new(),
            },
            aegis_domain::DepDelta::Upgraded { prev, next } => {
                let (v, risk, drift, rf, df) = score_diff_entry(next, Some(prev), &allow);
                if v == VerdictKind::Block {
                    any_blocked = true;
                }
                if v == VerdictKind::Prompt {
                    any_prompt = true;
                }
                DiffEntryView {
                    kind: "upgraded",
                    ecosystem: next.ecosystem.as_str().to_string(),
                    name: next.name.clone(),
                    prev_version: prev.version.clone(),
                    next_version: next.version.clone(),
                    verdict: v.name().to_string(),
                    risk_score: risk,
                    drift_score: drift,
                    risk_flags: rf.iter().map(RiskFlagView::from).collect(),
                    drift_flags: df.iter().map(RiskFlagView::from).collect(),
                }
            }
        };
        views.push(view);
    }

    // Text rendering.
    if views.is_empty() {
        println!("no changes");
        return;
    }
    let mut printed = 0usize;
    for e in &views {
        let marker = match e.verdict.as_str() {
            "block" => "✗",
            "prompt" => "⚠",
            "review" => "~",
            _ => "✓",
        };
        let id = match e.kind {
            "added" => format!("+ {}/{}@{}", e.ecosystem, e.name, e.next_version),
            "removed" => format!("- {}/{}@{}", e.ecosystem, e.name, e.prev_version),
            "upgraded" => format!(
                "~ {}/{}@{} → {}",
                e.ecosystem, e.name, e.prev_version, e.next_version
            ),
            _ => format!("? {}/{}", e.ecosystem, e.name),
        };
        println!("{marker} {id}");
        if e.risk_score > 0
            || e.drift_score > 0
            || !e.risk_flags.is_empty()
            || !e.drift_flags.is_empty()
        {
            println!(
                "    └─ verdict={} risk={} drift={}",
                e.verdict, e.risk_score, e.drift_score
            );
            for f in &e.risk_flags {
                println!("       ! {} (+{}): {}", f.code, f.weight, f.detail);
            }
            for f in &e.drift_flags {
                println!("       ! {} (+{}): {}", f.code, f.weight, f.detail);
            }
        }
        printed += 1;
    }
    let _ = printed;
    if any_blocked {
        println!("verdict: BLOCK (at least one dep upgraded to Block)");
    } else if any_prompt {
        println!("verdict: PROMPT (at least one dep reached Prompt)");
    } else {
        println!("verdict: pass");
    }
}

/// Compute the (verdict, risk_score, drift_score, risk_flags, drift_flags)
/// tuple for one diff entry. `prev_fp` is None for Added entries. Mirrors
/// Go's per-entry `BuildDiff_report_from_snapshots` risk + drift folding:
/// risk = RiskScore(fp) + ProvenanceRiskFlag + Patch-drift flag applied;
/// drift = DriftScore(prev_fp, next_fp). Allow applies. Verdict = max(risk,
/// drift) bucketed.
fn score_diff_entry(
    next: &Dependency,
    prev: Option<&Dependency>,
    allow: &aegis_domain::AllowSet,
) -> (VerdictKind, i32, i32, Vec<RiskFlag>, Vec<RiskFlag>) {
    let next_fp = next.fingerprint.as_ref();
    let prev_fp = prev.and_then(|p| p.fingerprint.as_ref());
    let mut risk = risk_score(next_fp);
    // Provenance risk flag folds in (npm missing-attestation).
    if let Some(pf) = provenance_risk_flag(next) {
        risk.flags.push(pf.clone());
        risk.score += pf.weight;
    }
    // Patch-version drift flag (same-minor different-patch + gained cap).
    if let (Some(prev), Some(prev_fp), Some(next_fp)) = (prev, prev_fp, next_fp) {
        let added: CapabilitySet = next_fp.capabilities.difference(&prev_fp.capabilities);
        if let Some(flag) = patch_version_drift_flag(&prev.version, &next.version, &added) {
            risk.score += flag.weight;
            risk.flags.push(flag);
        }
    }
    // Apply allowlist (suppressed flags still rendered).
    let risk = apply_allowlist(&risk, allow, next.ecosystem, &next.name, &next.version);
    // Reachability downgrade — only when reached classification is Unused
    // AND the env says suppress (matching the ci contract). For diff the
    // default is to NOT suppress capability flags; we only downgrade the
    // advisory verdict below. Conservative (no-FN risk).
    let drift = drift_score(prev_fp, next_fp);
    let v = verdict(&risk, &drift);
    // Advisory verdict — fold in when next has been enriched with advisories.
    let mut adv_v = match next.advisories.as_ref() {
        Some(v) => verdict_for_advisories(v),
        None => VerdictKind::Safe,
    };
    if next.reachability == Reachability::Unused {
        adv_v = downgrade_verdict(adv_v);
    }
    (
        v.max(adv_v),
        risk.score,
        drift.score,
        risk.flags,
        drift.flags,
    )
}

// ---------- subcommand: enrich ----------

/// `aegis snapshot enrich` — fetch each dep's published source, AST + heuristics
/// scan it, fold in advisories (OSV + GHSA + EPSS + KEV), and classify
/// reachability — persisting the result in `aegis.lock` so the next `enrich`
/// run only processes deps that haven't been enriched yet (idempotent).
pub(crate) fn run_snapshot_enrich(project_dir: &str) -> ExitCode {
    let mut snap = match load_snapshot(project_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("aegis: no snapshot saved — run `aegis snapshot save` first");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    // Idempotency: pending deps are those that still need a fingerprint or an
    // advisory lookup. (Go's `Fingerprint==nil || !Analyzed` check — Rust
    // adds `advisories.is_none()` so rescan/enrich can run before advisories.)
    let pending_indices: Vec<usize> = snap
        .deps
        .iter()
        .enumerate()
        .filter(|(_, d)| d.fingerprint.is_none() || d.advisories.is_none())
        .map(|(i, _)| i)
        .collect();
    if pending_indices.is_empty() {
        println!("all deps enriched — nothing to do");
        return ExitCode::SUCCESS;
    }

    let dir = if project_dir.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(project_dir)
    };
    println!("enriching {} deps…", pending_indices.len());

    // Phase 1: per-dep fingerprint (fetch tarball + AST + heuristics), in
    // parallel via rayon. Each fetch is independent. Best-effort — a failed
    // fetch leaves the dep's fingerprint as `Some(analyzed:true)` to stop
    // re-runs from retrying (mirrors Go's "no language scanner" carve-out).
    let fprints: Vec<Option<Fingerprint>> = pending_indices
        .par_iter()
        .map(|&i| {
            let dep = &snap.deps[i];
            Some(enrich_dep_fingerprint(dep))
        })
        .collect();
    for (k, &i) in pending_indices.iter().enumerate() {
        if let Some(fp) = &fprints[k] {
            snap.deps[i].fingerprint = Some(fp.clone());
        } else {
            snap.deps[i].fingerprint = Some(Fingerprint {
                analyzed: true,
                ..Default::default()
            });
        }
    }

    // Phase 2: reachability classification — one source walk, classify each
    // dep Used/Unused for the languages aegis-reach parses (npm/pypi/go/
    // rubygems). Unknown stays otherwise.
    let reach = project_reachability(&dir);
    for d in &mut snap.deps {
        if reachability_eligible(d.ecosystem) {
            d.reachability = reach.classify(d);
        }
    }

    // Phase 3: advisories — one batched OSV+GHSA query + EPSS+KEV enrich.
    let queries: Vec<AdvisoryQuery> = snap
        .deps
        .iter()
        .filter(|d| d.advisories.is_none() && !d.version.is_empty())
        .map(|d| AdvisoryQuery {
            ecosystem: d.ecosystem,
            name: d.name.clone(),
            version: d.version.clone(),
        })
        .collect();
    if !queries.is_empty() {
        match advisories_by_key(&queries) {
            Ok(map) => {
                for d in &mut snap.deps {
                    if d.advisories.is_none() && !d.version.is_empty() {
                        let key = d.versioned_key();
                        let v = map.get(&key).cloned().unwrap_or_default();
                        d.advisories = Some(v);
                    }
                }
            }
            Err(e) => eprintln!("aegis: advisory lookup failed: {e} (continuing)"),
        }
    }
    // For deps that didn't get a query (empty version, or non-enriched), mark
    // them as advisory-looked-up so the next enrich doesn't retry.
    for d in &mut snap.deps {
        if d.advisories.is_none() {
            d.advisories = Some(Vec::new());
        }
    }

    // Persist partial progress (matches Go — save after each enrich phase).
    let path = lockfile_path(project_dir);
    if let Err(e) = save_snapshot(&path, &snap) {
        eprintln!("aegis: {e}");
        return ExitCode::from(2);
    }
    let enriched = pending_indices.len();
    println!("enriched {enriched} deps → {}", path.display());
    ExitCode::SUCCESS
}

/// Fetch a dep's published source, AST + heuristics scan it, and return the
/// fingerprint. Returns the analyzed-empty fingerprint on any fetch failure
/// (so a re-run doesn't retry) — matches Go's "no language scanner for the
/// ecosystem → set Analyzed:true, move on" carve-out. Best-effort: a single
/// bad dep never fails the batch. The allowlist is NOT applied here — it
/// folds in at verdict time (mirrors Go's enrich→verdict separation).
fn enrich_dep_fingerprint(dep: &Dependency) -> Fingerprint {
    if !is_enriched_ecosystem(dep.ecosystem) || dep.name.is_empty() || dep.version.is_empty() {
        return Fingerprint {
            analyzed: true,
            ..Default::default()
        };
    }
    let http = aegis_net::default_client();
    match crate::scan::fetch_source(&http, dep) {
        Ok(files) => fingerprint_source(&files, &dep.name, dep.ecosystem, Vec::new()),
        Err(_) => Fingerprint {
            analyzed: true,
            ..Default::default()
        },
    }
}

/// Ecosystems whose published source `enrich` can fetch + capability-scan.
/// Mirrors `scan::is_enriched_ecosystem` (kept here so the snapshot module
/// has a stable surface independent of scan.rs accessor re-exports).
fn is_enriched_ecosystem(eco: Ecosystem) -> bool {
    matches!(
        eco,
        Ecosystem::Npm | Ecosystem::PyPI | Ecosystem::Crates | Ecosystem::RubyGems | Ecosystem::Go
    )
}

// ---------- subcommand: rescan ----------

/// `aegis snapshot rescan` — re-query the advisory feed for every dep already
/// saved, diff against the previously-known advisory IDs, and exit 1 when any
/// new advisory appeared (the cron-page contract). Saves the updated
/// snapshot so a subsequent rescan starts from the new baseline.
pub(crate) fn run_snapshot_rescan(project_dir: &str, json: bool) -> ExitCode {
    let mut snap = match load_snapshot(project_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("aegis: no snapshot saved — run `aegis snapshot save` first");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let queries: Vec<AdvisoryQuery> = snap
        .deps
        .iter()
        .filter(|d| !d.version.is_empty())
        .map(|d| AdvisoryQuery {
            ecosystem: d.ecosystem,
            name: d.name.clone(),
            version: d.version.clone(),
        })
        .collect();
    let prev_ids: std::collections::HashMap<String, std::collections::HashSet<String>> = snap
        .deps
        .iter()
        .map(|d| {
            (
                d.versioned_key(),
                d.advisories
                    .as_ref()
                    .map(|v| v.iter().map(|a| a.id.clone()).collect())
                    .unwrap_or_default(),
            )
        })
        .collect();
    let new_map = match advisories_by_key(&queries) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("aegis: advisory lookup failed: {e}");
            return ExitCode::from(2);
        }
    };

    let mut findings: Vec<RescanFinding> = Vec::new();
    for d in &mut snap.deps {
        if d.version.is_empty() {
            continue;
        }
        let key = d.versioned_key();
        let now_advs = new_map.get(&key).cloned().unwrap_or_default();
        let prev = prev_ids.get(&key).cloned().unwrap_or_default();
        let new_advs: Vec<Advisory> = now_advs
            .iter()
            .filter(|a| !prev.contains(&a.id))
            .cloned()
            .collect();
        if !new_advs.is_empty() {
            findings.push(RescanFinding {
                ecosystem: d.ecosystem.as_str().to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
                new_advisories: new_advs.iter().map(adv_to_dto).collect(),
            });
        }
        d.advisories = Some(now_advs);
    }

    // Persist partial progress.
    let path = lockfile_path(project_dir);
    if let Err(e) = save_snapshot(&path, &snap) {
        eprintln!("aegis: {e}");
        return ExitCode::from(2);
    }
    let new_count = findings.len();

    if json {
        let report = RescanReport {
            total: snap.deps.len(),
            new_count,
            findings: findings.iter().map(RescanFindingView::from).collect(),
        };
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!("rescan: queried {} dep(s)", snap.deps.len());
        if new_count == 0 {
            println!("no new advisories found");
        } else {
            println!("{new_count} dep(s) have new advisories");
            for f in &findings {
                for a in &f.new_advisories {
                    println!(
                        "  [{}] {} — {}/{}@{}: {}",
                        a.severity, a.id, f.ecosystem, f.name, f.version, a.summary
                    );
                }
            }
        }
    }

    if new_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

struct RescanFinding {
    ecosystem: String,
    name: String,
    version: String,
    new_advisories: Vec<AdvisoryDto>,
}

#[derive(Serialize)]
struct RescanReport {
    total: usize,
    new_count: usize,
    findings: Vec<RescanFindingView>,
}

#[derive(Serialize)]
struct RescanFindingView {
    ecosystem: String,
    name: String,
    version: String,
    new_advisories: Vec<AdvisoryDto>,
}

impl From<&RescanFinding> for RescanFindingView {
    fn from(f: &RescanFinding) -> Self {
        RescanFindingView {
            ecosystem: f.ecosystem.clone(),
            name: f.name.clone(),
            version: f.version.clone(),
            new_advisories: f.new_advisories.clone(),
        }
    }
}

// ---------- subcommand: capture (the Rust-specific single-package mode) ----------

/// A package's behavioral fingerprint persisted as the Rust-specific
/// single-package `snapshot capture` shape. Kept back-compatible with the
/// existing `snapshot <dir>` baseline format, so older baselines loaded.
#[derive(Serialize, Deserialize)]
struct CaptureSchema {
    ecosystem: String,
    score: i32,
    capabilities: Vec<String>,
    #[serde(default)]
    source_size_bytes: i64,
    #[serde(default)]
    hooks: Vec<CaptureHook>,
}

#[derive(Serialize, Deserialize)]
struct CaptureHook {
    phase: String,
    source: String,
    sha256: String,
}

impl CaptureSchema {
    fn to_fingerprint(&self) -> Fingerprint {
        let caps: Vec<Capability> = self
            .capabilities
            .iter()
            .filter_map(|c| Capability::from_name(c))
            .collect();
        let hooks = self
            .hooks
            .iter()
            .map(|h| InstallHook {
                phase: hook_phase_from_dto(&h.phase),
                source: h.source.clone(),
                sha256: h.sha256.clone(),
            })
            .collect();
        Fingerprint {
            analyzed: true,
            capabilities: CapabilitySet::new(caps),
            env_reads: Vec::new(),
            source_size_bytes: self.source_size_bytes,
            hooks,
        }
    }
}

/// `aegis snapshot capture <dir> [--ecosystem] [--out FILE] [--baseline FILE]`
/// — the Rust-specific single-package capability fingerprint mode the `snapshot`
/// verb used to be. Behavioral drift between versions (a new capability
/// appearing) is the canonical maintainer-takeover signal (event-stream
/// shipped `child_process`/`net` it never had). Exits 1 when any *new* risky
/// capability appeared, OR any install-hook add/change.
pub(crate) fn run_snapshot_capture(
    dir: &str,
    ecosystem: &str,
    out: Option<&str>,
    baseline: Option<&str>,
) -> ExitCode {
    let root = Path::new(dir);
    if !root.is_dir() {
        eprintln!("aegis: not a directory: {dir}");
        return ExitCode::from(2);
    }
    let Some(eco) = parse_ecosystem(ecosystem) else {
        eprintln!("aegis: unknown ecosystem: {ecosystem}");
        return ExitCode::from(2);
    };
    let pkg_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let files = collect_files(root);
    let fp = fingerprint_source(&files, &pkg_name, eco, Vec::new());
    let assessment = risk_score(Some(&fp));
    let snap = CaptureSchema {
        ecosystem: eco.as_str().to_string(),
        score: assessment.score,
        capabilities: fp
            .capabilities
            .iter()
            .map(|c| c.name().to_string())
            .collect(),
        source_size_bytes: fp.source_size_bytes,
        hooks: fp
            .hooks
            .iter()
            .map(|h| CaptureHook {
                phase: h.phase.name().to_string(),
                source: h.source.clone(),
                sha256: h.sha256.clone(),
            })
            .collect(),
    };

    if let Some(base_path) = baseline {
        let base_bytes = match std::fs::read(base_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("aegis: cannot read baseline {base_path}: {e}");
                return ExitCode::from(2);
            }
        };
        let base: CaptureSchema = match serde_json::from_slice(&base_bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("aegis: invalid baseline {base_path}: {e}");
                return ExitCode::from(2);
            }
        };
        let base_set: std::collections::HashSet<&str> =
            base.capabilities.iter().map(String::as_str).collect();
        let now_set: std::collections::HashSet<&str> =
            snap.capabilities.iter().map(String::as_str).collect();
        let added: Vec<&str> = snap
            .capabilities
            .iter()
            .map(String::as_str)
            .filter(|c| !base_set.contains(c))
            .collect();
        let removed: Vec<&str> = base
            .capabilities
            .iter()
            .map(String::as_str)
            .filter(|c| !now_set.contains(c))
            .collect();

        let drift = drift_score(Some(&base.to_fingerprint()), Some(&fp));

        if added.is_empty() && removed.is_empty() && drift.flags.is_empty() {
            println!(
                "no behavioral drift ({} capabilities)",
                snap.capabilities.len()
            );
            return ExitCode::SUCCESS;
        }
        for c in &added {
            println!("+ {c}  (NEW capability — possible takeover)");
        }
        for c in &removed {
            println!("- {c}  (removed)");
        }
        for f in &drift.flags {
            if f.code != "capability-added" {
                println!("! {} (+{}): {}", f.code, f.weight, f.detail);
            }
        }
        if drift.score > 0 {
            println!("drift score: {}", drift.score);
        }
        let hook_drift = drift
            .flags
            .iter()
            .any(|f| f.code.starts_with("install-hook"));
        return if added.is_empty() && !hook_drift {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    let json = match serde_json::to_string_pretty(&snap) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aegis: json encode failed: {e}");
            return ExitCode::from(2);
        }
    };
    match out {
        Some(path) => match std::fs::write(path, &json) {
            Ok(()) => println!("wrote snapshot → {path}"),
            Err(e) => {
                eprintln!("aegis: cannot write {path}: {e}");
                return ExitCode::from(2);
            }
        },
        None => println!("{json}"),
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(eco: Ecosystem, name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem: eco,
            name: name.to_string(),
            version: version.to_string(),
            ..Default::default()
        }
    }

    fn scratch() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "aegis-snap-ut-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn save_and_load_roundtrips() {
        let dir = scratch();
        let snap = DomainSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            aegis_version: "0.0.0-test".to_string(),
            project: "demo".to_string(),
            deps: vec![
                dep(Ecosystem::Npm, "lodash", "4.17.21"),
                dep(Ecosystem::PyPI, "requests", "2.31.0"),
            ],
        };
        let path = dir.join(LOCKFILE_NAME);
        save_snapshot(&path, &snap).unwrap();
        let loaded = load_snapshot_file(&path).unwrap().unwrap();
        assert_eq!(loaded.schema_version, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(loaded.project, "demo");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.deps[0].name, "lodash");
        assert_eq!(loaded.deps[1].ecosystem, Ecosystem::PyPI);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_is_none() {
        let dir = scratch();
        let path = dir.join("nope.lock");
        assert!(load_snapshot_file(&path).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_compressed_rejected_with_clear_message() {
        let dir = scratch();
        let path = dir.join(LOCKFILE_NAME);
        // zstd magic + some bytes
        std::fs::write(&path, [0x28u8, 0xB5, 0x2F, 0xFD, 0x00, 0x00]).unwrap();
        let err = load_snapshot_file(&path).unwrap_err();
        assert!(err.contains("compressed"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_roundtrips_through_dto() {
        let fp = Fingerprint {
            analyzed: true,
            capabilities: CapabilitySet::new([Capability::ShellSpawn, Capability::NetEgress]),
            hooks: vec![InstallHook {
                phase: HookPhase::PostInstall,
                source: "scripts.postinstall".into(),
                sha256: "abc".into(),
            }],
            env_reads: vec!["AWS_ACCESS_KEY_ID".into()],
            source_size_bytes: 1234,
        };
        let dto = fp_to_dto(&fp);
        let back = fp_from_dto(&dto);
        assert_eq!(back.analyzed, fp.analyzed);
        assert_eq!(back.capabilities, fp.capabilities);
        assert_eq!(back.hooks, fp.hooks);
        assert_eq!(back.env_reads, fp.env_reads);
        assert_eq!(back.source_size_bytes, fp.source_size_bytes);
    }

    #[test]
    fn advisory_roundtrips_through_dto() {
        let a = Advisory {
            id: "GHSA-x".into(),
            aliases: vec!["CVE-2024-1".into()],
            severity: aegis_domain::Severity::High,
            summary: "bad".into(),
            url: "https://x".into(),
            source: "ghsa".into(),
            fixed_in: "1.2.3".into(),
            affected_functions: vec!["foo".into()],
            epss: 0.42,
            epss_percentile: 0.9,
            in_kev: true,
        };
        let dto = adv_to_dto(&a);
        let back = adv_from_dto(&dto);
        assert_eq!(back, a);
    }

    #[test]
    fn dependency_roundtrips_advisory_fingerprint_enrichment() {
        let mut d = dep(Ecosystem::Npm, "lodash", "4.17.4");
        d.fingerprint = Some(Fingerprint {
            analyzed: true,
            capabilities: CapabilitySet::new([Capability::DynamicEval]),
            source_size_bytes: 500,
            ..Default::default()
        });
        d.advisories = Some(vec![Advisory {
            id: "GHSA-1".into(),
            severity: aegis_domain::Severity::High,
            ..Default::default()
        }]);
        d.reachability = Reachability::Used;
        d.deprecated = true;
        d.deprecated_reason = "use lodash-es".into();
        d.provenance_status = "missing".into();
        let dto = dep_to_dto(&d);
        let back = dep_from_dto(&dto);
        assert_eq!(back.ecosystem, d.ecosystem);
        assert_eq!(back.name, d.name);
        assert!(back.fingerprint.is_some());
        assert_eq!(back.advisories.as_ref().unwrap().len(), 1);
        assert_eq!(back.reachability, Reachability::Used);
        assert!(back.deprecated);
        assert_eq!(back.provenance_status, "missing");
    }

    #[test]
    fn nil_vs_empty_advisories_preserved_through_roundtrip() {
        // None  -> omitted in JSON -> None on load
        // Some(empty) -> `"advisories": []` -> Some(empty) on load
        let d_none = dep(Ecosystem::Npm, "a", "1");
        let dto = dep_to_dto(&d_none);
        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("advisories"),
            "None should be omitted: {json}"
        );
        let back = dep_from_dto(&serde_json::from_str::<DepDto>(&json).unwrap());
        assert!(back.advisories.is_none(), "should round-trip to None");

        let d_empty = Dependency {
            advisories: Some(Vec::new()),
            ..dep(Ecosystem::Npm, "a", "1")
        };
        let dto = dep_to_dto(&d_empty);
        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            json.contains("\"advisories\":[]"),
            "Some(empty) should be []: {json}"
        );
        let back = dep_from_dto(&serde_json::from_str::<DepDto>(&json).unwrap());
        assert_eq!(back.advisories, Some(Vec::new()));
    }
}
