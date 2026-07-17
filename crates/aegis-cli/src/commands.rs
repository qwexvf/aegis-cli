//! Command handlers for the `aegis` CLI plus the serde view/config structs
//! they own. Each `run_*` fn maps one CLI subcommand to a process exit code.

use std::path::Path;
use std::process::ExitCode;

use aegis_domain::{
    build_fix_plan, builtin_allow_rules, risk_score, upgrade_command, verdict, AdvisoryQuery,
    Capability, CapabilitySet, Dependency, Fingerprint, RiskAssessment, Severity, ALL_CAPABILITIES,
};
use aegis_lockfile::{parse_file, DirectMap};
use aegis_net::UreqClient;
use aegis_vuln::OsvClient;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::enrich::{ci_findings_to_sarif, cve_findings, osv_disk_cache};
use crate::scan::{collect_files, fetch_online_caps, lockfile_deps, scan_source};
use crate::util::{parse_ecosystem, parse_severity, severity_rank};

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

#[derive(Serialize)]
pub(crate) struct FindingView {
    pub(crate) ecosystem: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) advisory: String,
    pub(crate) severity: String,
    pub(crate) summary: String,
    pub(crate) fixed_in: String,
    /// EPSS exploit probability (0–1); 0 = unscored.
    pub(crate) epss: f64,
    /// true when the CVE is in CISA's Known Exploited Vulnerabilities catalog.
    pub(crate) in_kev: bool,
}

#[derive(Serialize)]
struct CiView {
    fail_on: String,
    failed: bool,
    findings: Vec<FindingView>,
}

pub(crate) fn run_ci(
    file: &str,
    fail_on: &str,
    offline: bool,
    json: bool,
    sarif: bool,
) -> ExitCode {
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
        match cve_findings(&queries) {
            Ok(f) => findings = f,
            Err(e) => {
                eprintln!("aegis: CVE lookup failed: {e}");
                return ExitCode::from(2);
            }
        }
    }

    // Gate: fail when any finding meets the severity threshold.
    let failed = findings.iter().any(|f| {
        parse_severity(&f.severity)
            .map(|s| severity_rank(s) >= severity_rank(threshold))
            .unwrap_or(false)
    });

    if sarif {
        println!("{}", ci_findings_to_sarif(&findings));
        return if failed {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }
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

// --- config-driven task runner -------------------------------------

/// Parsed `aegis.toml`. Declares scan tasks; independent tasks fan out.
#[derive(Deserialize)]
struct AegisConfig {
    /// "auto" (all cores, default) or a thread count.
    #[serde(default)]
    parallelism: Option<toml::Value>,
    #[serde(default, rename = "task")]
    tasks: Vec<TaskConfig>,
}

#[derive(Deserialize)]
struct TaskConfig {
    name: String,
    path: String,
    #[serde(default = "crate::util::default_ecosystem")]
    ecosystem: String,
    /// which checks to run: "ast"/"heuristics" (source scan), "cve",
    /// "deprecated", and/or "license".
    #[serde(default)]
    checks: Vec<String>,
    /// SPDX license IDs that fail the "license" check (case-insensitive).
    #[serde(default)]
    deny_licenses: Vec<String>,
}

#[derive(Serialize)]
struct TaskResult {
    name: String,
    path: String,
    /// source-scan verdict, when ast/heuristics ran.
    verdict: Option<String>,
    score: i32,
    /// CVE findings count, when the cve check ran.
    cve_findings: usize,
    /// Deprecated-dependency count, when the deprecated check ran.
    #[serde(default)]
    deprecated_findings: usize,
    /// Denied-license count, when the license check ran.
    #[serde(default)]
    license_findings: usize,
    failed: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct RunView {
    failed: bool,
    tasks: Vec<TaskResult>,
}

/// Run one task: collect its files once, then run the checks it declares.
fn run_task(t: &TaskConfig) -> TaskResult {
    let mut res = TaskResult {
        name: t.name.clone(),
        path: t.path.clone(),
        verdict: None,
        score: 0,
        cve_findings: 0,
        deprecated_findings: 0,
        license_findings: 0,
        failed: false,
        error: None,
    };
    let root = Path::new(&t.path);
    if !root.is_dir() {
        res.error = Some(format!("not a directory: {}", t.path));
        res.failed = true;
        return res;
    }
    let Some(eco) = parse_ecosystem(&t.ecosystem) else {
        res.error = Some(format!("unknown ecosystem: {}", t.ecosystem));
        res.failed = true;
        return res;
    };
    let files = collect_files(root);
    let want = |c: &str| t.checks.iter().any(|x| x == c);

    // Source scan (ast + heuristics).
    if want("ast") || want("heuristics") {
        let (_caps, assessment) = scan_source(&files, &t.name, eco, Vec::new());
        let v = verdict(&assessment, &RiskAssessment::default());
        res.verdict = Some(v.name().to_string());
        res.score = assessment.score;
        if matches!(v, aegis_domain::VerdictKind::Block) {
            res.failed = true;
        }
    }

    // CVE lookup over any lockfiles found in the task path.
    if want("cve") {
        let queries: Vec<AdvisoryQuery> = lockfile_deps(&files)
            .into_iter()
            .filter(|d| !d.version.is_empty())
            .map(|d| AdvisoryQuery {
                ecosystem: d.ecosystem,
                name: d.name,
                version: d.version,
            })
            .collect();
        if !queries.is_empty() {
            match cve_findings(&queries) {
                Ok(findings) => {
                    res.cve_findings = findings.len();
                    // Fail the task on any high/critical CVE.
                    if findings.iter().any(|f| {
                        parse_severity(&f.severity)
                            .map(|s| severity_rank(s) >= severity_rank(Severity::High))
                            .unwrap_or(false)
                    }) {
                        res.failed = true;
                    }
                }
                Err(e) => {
                    res.error = Some(format!("cve lookup: {e}"));
                }
            }
        }
    }

    // Deprecation check over any lockfiles found in the task path (deps.dev).
    if want("deprecated") {
        let deps = lockfile_deps(&files);
        if !deps.is_empty() {
            let http = UreqClient::new();
            let client = aegis_registry::DepsDevClient::default();
            let deprecated = deps
                .iter()
                .filter(|d| !d.version.is_empty())
                .filter(|d| {
                    client
                        .fetch_health(&http, d.ecosystem, &d.name, &d.version)
                        .map(|h| h.is_deprecated)
                        .unwrap_or(false)
                })
                .count();
            res.deprecated_findings = deprecated;
            if deprecated > 0 {
                res.failed = true;
            }
        }
    }

    // License-policy check: fail on any dep whose SPDX license is denied.
    if want("license") && !t.deny_licenses.is_empty() {
        let deny: Vec<String> = t.deny_licenses.iter().map(|s| s.to_lowercase()).collect();
        let deps = lockfile_deps(&files);
        if !deps.is_empty() {
            let http = UreqClient::new();
            let fetcher = aegis_registry::LicenseFetcher::default();
            let violations = deps
                .iter()
                .filter(|d| !d.version.is_empty())
                .filter(|d| {
                    fetcher
                        .fetch_license(&http, d.ecosystem, &d.name, &d.version)
                        .map(|lic| deny.contains(&lic.to_lowercase()))
                        .unwrap_or(false)
                })
                .count();
            res.license_findings = violations;
            if violations > 0 {
                res.failed = true;
            }
        }
    }

    res
}

pub(crate) fn run_config(config_path: &str, json: bool) -> ExitCode {
    let text = match std::fs::read_to_string(config_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("aegis: cannot read {config_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let config: AegisConfig = match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aegis: invalid config {config_path}: {e}");
            return ExitCode::from(2);
        }
    };
    if config.tasks.is_empty() {
        eprintln!("aegis: no [[task]] entries in {config_path}");
        return ExitCode::from(2);
    }

    // Optional explicit thread count; default = rayon's all-cores pool.
    if let Some(toml::Value::Integer(n)) = config.parallelism {
        if n > 0 {
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(n as usize)
                .build_global();
        }
    }

    // Independent tasks run in PARALLEL (each task's source scan also fans out).
    let results: Vec<TaskResult> = config.tasks.par_iter().map(run_task).collect();
    let failed = results.iter().any(|r| r.failed);

    if json {
        let view = RunView {
            failed,
            tasks: results,
        };
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        for r in &results {
            let status = if r.failed { "FAIL" } else { "ok" };
            let verdict = r.verdict.as_deref().unwrap_or("-");
            print!(
                "[{status}] {} ({}) — verdict={verdict} score={} cve={} deprecated={} license={}",
                r.name, r.path, r.score, r.cve_findings, r.deprecated_findings, r.license_findings
            );
            match &r.error {
                Some(e) => println!("  error: {e}"),
                None => println!(),
            }
        }
        println!("overall: {}", if failed { "FAIL" } else { "pass" });
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub(crate) fn run_analyze(
    dir: &str,
    name: Option<&str>,
    ecosystem: &str,
    online: bool,
    json: bool,
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
    let pkg_name = name
        .map(String::from)
        .or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();

    let files = collect_files(root);
    let extra_caps = if online {
        fetch_online_caps(&files, &pkg_name, eco)
    } else {
        Vec::new()
    };
    let (caps, mut assessment) = scan_source(&files, &pkg_name, eco, extra_caps);
    // Online npm packages get an SLSA-provenance check: a missing attestation
    // adds the `provenance-missing` flag + its weight before the verdict.
    if online {
        if let Some(flag) = crate::scan::provenance_flag(&files, &pkg_name, eco) {
            assessment.score += flag.weight;
            assessment.flags.push(flag);
        }
    }
    let v = verdict(&assessment, &RiskAssessment::default());

    if json {
        let view = AnalysisView {
            verdict: v.name().to_string(),
            score: assessment.score,
            capabilities: caps.iter().map(|c| c.name().to_string()).collect(),
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

#[derive(Serialize)]
struct FixItemView {
    ecosystem: String,
    name: String,
    current_version: String,
    target_version: String,
    resolved: usize,
    unresolved: usize,
    /// Ecosystem-appropriate upgrade command, when one is known + shell-safe.
    command: Option<String>,
}

/// Suggest version bumps that resolve known CVEs. Parses the lockfile, looks up
/// advisories (OSV), groups them per dep, and computes the minimal forward
/// upgrade. `--script` emits just the shell commands (safe to pipe to sh).
pub(crate) fn run_fix(file: &str, offline: bool, script: bool, json: bool) -> ExitCode {
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

    // Advisory lookup (skipped offline → empty plan).
    let mut pairs: Vec<(Dependency, Vec<aegis_domain::Advisory>)> = Vec::new();
    if !offline {
        let queries: Vec<AdvisoryQuery> = deps
            .iter()
            .filter(|d| !d.version.is_empty())
            .map(|d| AdvisoryQuery {
                ecosystem: d.ecosystem,
                name: d.name.clone(),
                version: d.version.clone(),
            })
            .collect();
        if !queries.is_empty() {
            let client = UreqClient::new();
            match OsvClient::default()
                .with_cache(osv_disk_cache())
                .lookup(&client, &queries)
            {
                Ok(results) => {
                    for d in &deps {
                        if d.version.is_empty() {
                            continue;
                        }
                        let key = AdvisoryQuery {
                            ecosystem: d.ecosystem,
                            name: d.name.clone(),
                            version: d.version.clone(),
                        }
                        .key();
                        if let Some(advs) = results.get(&key) {
                            if !advs.is_empty() {
                                pairs.push((d.clone(), advs.clone()));
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("aegis: CVE lookup failed: {e}");
                    return ExitCode::from(2);
                }
            }
        }
    }

    let plan = build_fix_plan(&pairs);

    if script {
        for item in &plan {
            if let Some(cmd) = upgrade_command(&item.dep, &item.target_version) {
                println!("{cmd}");
            }
        }
        return ExitCode::SUCCESS;
    }

    if json {
        let view: Vec<FixItemView> = plan
            .iter()
            .map(|item| FixItemView {
                ecosystem: item.dep.ecosystem.as_str().to_string(),
                name: item.dep.name.clone(),
                current_version: item.dep.version.clone(),
                target_version: item.target_version.clone(),
                resolved: item.resolved.len(),
                unresolved: item.unresolved.len(),
                command: upgrade_command(&item.dep, &item.target_version),
            })
            .collect();
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else if plan.is_empty() {
        println!("no known-vulnerable dependencies with an upgrade path");
    } else {
        for item in &plan {
            let d = &item.dep;
            if item.target_version.is_empty() {
                println!(
                    "{}/{}@{} — {} advisory(ies), no forward fix (manual review)",
                    d.ecosystem.as_str(),
                    d.name,
                    d.version,
                    item.unresolved.len()
                );
            } else {
                println!(
                    "{}/{}@{} → {} (resolves {}{})",
                    d.ecosystem.as_str(),
                    d.name,
                    d.version,
                    item.target_version,
                    item.resolved.len(),
                    if item.unresolved.is_empty() {
                        String::new()
                    } else {
                        format!(", {} still unresolved", item.unresolved.len())
                    }
                );
                if let Some(cmd) = upgrade_command(d, &item.target_version) {
                    println!("    {cmd}");
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// Emit an SBOM (CycloneDX 1.5 or SPDX 2.3, JSON) for a lockfile's dep graph.
pub(crate) fn run_sbom(
    file: &str,
    format: &str,
    project: Option<&str>,
    serial: Option<&str>,
) -> ExitCode {
    let fmt = format.to_ascii_lowercase();
    if fmt != "cyclonedx" && fmt != "spdx" {
        eprintln!("aegis: unknown sbom format '{format}' (want cyclonedx|spdx)");
        return ExitCode::from(2);
    }
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

    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let project = project.unwrap_or_default().to_string();
    let serial_number = serial.unwrap_or_default().to_string();

    let out = if fmt == "spdx" {
        aegis_sbom::spdx::build_json(
            &deps,
            &aegis_sbom::spdx::Options {
                aegis_version: version,
                project,
                timestamp,
                serial_number,
            },
        )
    } else {
        aegis_sbom::cyclonedx::build_json(
            &deps,
            &aegis_sbom::cyclonedx::Options {
                aegis_version: version,
                project,
                timestamp,
                serial_number,
            },
        )
    };
    println!("{out}");
    ExitCode::SUCCESS
}

#[derive(Serialize)]
struct AllowRuleView {
    ecosystem: String,
    name: String,
    version_range: String,
    /// Suppressed capability, or null for "any capability".
    capability: Option<String>,
    reason: String,
    source: String,
}

/// List the built-in capability-suppression allowlist rules. These are the
/// curated defaults (e.g. known-good npm packages whose flagged capabilities
/// are expected) that the risk engine treats as pre-approved.
pub(crate) fn run_allowlist(json: bool) -> ExitCode {
    let rules = builtin_allow_rules();
    if json {
        let view: Vec<AllowRuleView> = rules
            .iter()
            .map(|r| AllowRuleView {
                ecosystem: r.ecosystem.as_str().to_string(),
                name: r.name.clone(),
                version_range: r.version_range.clone(),
                capability: r.capability.map(|c| c.name().to_string()),
                reason: r.reason.clone(),
                source: r.source.clone(),
            })
            .collect();
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!("{} built-in allowlist rules:", rules.len());
        for r in &rules {
            let cap = r.capability.map(|c| c.name()).unwrap_or("*");
            println!(
                "  {}/{} {} — suppress {} ({})",
                r.ecosystem.as_str(),
                r.name,
                r.version_range,
                cap,
                r.reason
            );
        }
    }
    ExitCode::SUCCESS
}

#[derive(Serialize)]
struct ImageFindingView {
    path: String,
    reason: String,
}

/// Scan an OCI / `docker save` image tarball: extract the flattened root
/// filesystem (layer overlay + whiteouts) and report risky files. Exit 1 when
/// any finding is present, 0 when clean, 2 on a read/parse error.
pub(crate) fn run_image(file: Option<&str>, reference: Option<&str>, json: bool) -> ExitCode {
    let img = match (file, reference) {
        (Some(path), None) => match aegis_image::extract_image_from_path(Path::new(path)) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("aegis: cannot read image {path}: {e}");
                return ExitCode::from(2);
            }
        },
        (None, Some(r)) => {
            let client = UreqClient::new();
            match aegis_image::pull_image(&client, r) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("aegis: cannot pull image {r}: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!("aegis: provide exactly one of an image tarball path or --ref <repo:tag>");
            return ExitCode::from(2);
        }
    };
    // All three tiers: shallow file-shape checks, source-pattern heuristics,
    // and tree-sitter AST capabilities. Deduped by (path, reason).
    let mut findings = aegis_image::scan_image_files(&img);
    findings.extend(aegis_image::deep_scan_image_files(&img));
    findings.extend(aegis_image::ast_scan_image_files(&img));
    findings.sort_by(|a, b| a.path.cmp(&b.path).then(a.reason.cmp(&b.reason)));
    findings.dedup_by(|a, b| a.path == b.path && a.reason == b.reason);

    if json {
        let view: Vec<ImageFindingView> = findings
            .iter()
            .map(|f| ImageFindingView {
                path: f.path.clone(),
                reason: f.reason.clone(),
            })
            .collect();
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else if findings.is_empty() {
        println!("no risky files found in image");
    } else {
        println!("{} risky file(s) in image:", findings.len());
        for f in &findings {
            println!("  {} — {}", f.path, f.reason);
        }
    }

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[derive(Serialize)]
struct CapabilityDoc {
    capability: String,
    description: String,
    /// score contribution when this capability is present on an analyzed package.
    weight: i32,
}

/// A capability's score weight, derived from the real scorer: a fingerprint
/// carrying only that capability scores exactly its contribution.
fn capability_weight(cap: Capability) -> i32 {
    let fp = Fingerprint {
        analyzed: true,
        capabilities: CapabilitySet::new([cap]),
        ..Default::default()
    };
    risk_score(Some(&fp)).score
}

fn capability_doc(cap: Capability) -> CapabilityDoc {
    CapabilityDoc {
        capability: cap.name().to_string(),
        description: cap.description().to_string(),
        weight: capability_weight(cap),
    }
}

/// Explain the risk model: list every capability (or one named slug) with its
/// meaning and score weight, ordered by weight descending.
pub(crate) fn run_explain(capability: Option<&str>, json: bool) -> ExitCode {
    let mut docs: Vec<CapabilityDoc> = match capability {
        Some(slug) => {
            let Some(cap) = ALL_CAPABILITIES.iter().copied().find(|c| c.name() == slug) else {
                eprintln!("aegis: unknown capability: {slug}");
                return ExitCode::from(2);
            };
            vec![capability_doc(cap)]
        }
        None => ALL_CAPABILITIES
            .iter()
            .copied()
            .map(capability_doc)
            .collect(),
    };
    docs.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then(a.capability.cmp(&b.capability))
    });

    if json {
        match serde_json::to_string_pretty(&docs) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        for d in &docs {
            println!("[{:>3}] {} — {}", d.weight, d.capability, d.description);
        }
    }
    ExitCode::SUCCESS
}

#[derive(Serialize)]
struct ReachView {
    package: String,
    reachable: bool,
    reachability: String,
}

/// Report whether `package` is imported anywhere in the project's JS/TS source
/// (reachability). Exit 0 = reachable (used), 1 = unreachable (unused code the
/// risk engine can downgrade), 2 = not a directory.
pub(crate) fn run_reach(dir: &str, package: &str, json: bool) -> ExitCode {
    let root = Path::new(dir);
    if !root.is_dir() {
        eprintln!("aegis: not a directory: {dir}");
        return ExitCode::from(2);
    }
    let files = collect_files(root);
    let reach = aegis_reach::reachability_of(package, &files);
    let reachable = matches!(reach, aegis_domain::Reachability::Used);

    if json {
        let view = ReachView {
            package: package.to_string(),
            reachable,
            reachability: format!("{reach:?}").to_lowercase(),
        };
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else if reachable {
        println!("{package}: reachable (imported in project source)");
    } else {
        println!("{package}: unreachable (not imported — risk can be downgraded)");
    }

    if reachable {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// The git pre-commit hook body: fail the commit if any tracked lockfile has
/// a high/critical known vulnerability.
const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# aegis supply-chain pre-commit hook — blocks commits that add a known-
# vulnerable dependency. Generated by `aegis hook`.
set -e
for lock in $(git diff --cached --name-only --diff-filter=ACM | grep -E '(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|requirements\.txt|poetry\.lock|Gemfile\.lock|composer\.lock)$' || true); do
  [ -f "$lock" ] || continue
  echo "aegis: scanning $lock"
  aegis ci "$lock" --fail-on high || {
    echo "aegis: commit blocked — high/critical vulnerability in $lock" >&2
    exit 1
  }
done
exit 0
"#;

/// The GitHub Actions workflow: run the CI gate on push/PR and upload SARIF to
/// the Security tab.
const ACTIONS_WORKFLOW: &str = r#"# .github/workflows/aegis.yml — generated by `aegis actions`
name: aegis supply-chain scan
on:
  push:
    branches: [main]
  pull_request:
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - name: Install aegis
        run: cargo install --git https://github.com/qwexvf/aegis-cli
      - name: Scan lockfile
        run: aegis ci package-lock.json --fail-on high --sarif > aegis.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aegis.sarif
"#;

/// Print the git pre-commit hook, or install it to `.git/hooks/pre-commit`.
pub(crate) fn run_hook(install: bool) -> ExitCode {
    if !install {
        print!("{PRE_COMMIT_HOOK}");
        return ExitCode::SUCCESS;
    }
    let hooks_dir = Path::new(".git").join("hooks");
    if !Path::new(".git").is_dir() {
        eprintln!("aegis: not a git repository (no .git directory)");
        return ExitCode::from(2);
    }
    if let Err(e) = std::fs::create_dir_all(&hooks_dir) {
        eprintln!("aegis: cannot create {}: {e}", hooks_dir.display());
        return ExitCode::from(2);
    }
    let path = hooks_dir.join("pre-commit");
    if let Err(e) = std::fs::write(&path, PRE_COMMIT_HOOK) {
        eprintln!("aegis: cannot write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    println!("installed pre-commit hook → {}", path.display());
    ExitCode::SUCCESS
}

/// Print a ready-to-commit GitHub Actions workflow.
pub(crate) fn run_actions() -> ExitCode {
    print!("{ACTIONS_WORKFLOW}");
    ExitCode::SUCCESS
}

/// A package's behavioral fingerprint: the capabilities its code exercises plus
/// the risk score. Persisted so a later run can diff against it.
#[derive(Serialize, Deserialize)]
struct Snapshot {
    ecosystem: String,
    score: i32,
    capabilities: Vec<String>,
}

/// Fingerprint a package (or diff it against a baseline). Behavioral drift — a
/// new capability appearing between versions — is the canonical maintainer-
/// takeover signal (event-stream shipped `child_process`/`net` it never had).
/// With `--baseline`, exits 1 when any *new* capability appears.
pub(crate) fn run_snapshot(
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
    let (caps, assessment) = scan_source(&files, &pkg_name, eco, Vec::new());
    let snap = Snapshot {
        ecosystem: eco.as_str().to_string(),
        score: assessment.score,
        capabilities: caps.iter().map(|c| c.name().to_string()).collect(),
    };

    // Diff mode: compare current capabilities against the baseline's.
    if let Some(base_path) = baseline {
        let base_bytes = match std::fs::read(base_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("aegis: cannot read baseline {base_path}: {e}");
                return ExitCode::from(2);
            }
        };
        let base: Snapshot = match serde_json::from_slice(&base_bytes) {
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

        if added.is_empty() && removed.is_empty() {
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
        // New capabilities are the risk signal; removals alone are fine.
        return if added.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    // Capture mode: write or print the fingerprint.
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

pub(crate) fn run_parse(file: &str, json: bool) -> ExitCode {
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
