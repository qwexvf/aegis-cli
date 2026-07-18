//! Command handlers for the `aegis` CLI plus the serde view/config structs
//! they own. Each `run_*` fn maps one CLI subcommand to a process exit code.

use std::path::Path;
use std::process::ExitCode;

use aegis_domain::{
    build_fix_plan, builtin_allow_rules, risk_score, upgrade_command, verdict,
    verdict_for_advisories, Advisory, AdvisoryQuery, Capability, CapabilitySet, Dependency,
    Fingerprint, RiskAssessment, Severity, VerdictKind, ALL_CAPABILITIES,
};
use aegis_lockfile::{parse_file, DirectMap};
use aegis_net::UreqClient;
use aegis_vuln::OsvClient;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::enrich::{advisories_by_key, ci_findings_to_sarif, cve_findings, osv_disk_cache};
use crate::scan::{collect_files, enrich_dep, fetch_online_caps, lockfile_deps, scan_source};
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

/// Go-shaped `ci --json` report: a per-verdict summary over the whole project
/// plus the findings that meet the fail-on threshold. Mirrors the Go CI
/// presenter so the two are diffable.
#[derive(Serialize)]
struct CiReport {
    project: String,
    fail_on: String,
    enriched: bool,
    passed: bool,
    summary: CiSummary,
    findings: Vec<CiFinding>,
}

#[derive(Serialize)]
struct CiSummary {
    total: usize,
    safe: usize,
    review: usize,
    prompt: usize,
    blocked: usize,
}

#[derive(Serialize)]
struct CiFinding {
    ecosystem: String,
    name: String,
    version: String,
    direct: bool,
    verdict: String,
    risk_score: i32,
    flags: Vec<CiFlag>,
    advisories: Vec<CiAdvisory>,
}

/// A ci finding's risk flag — Go shape `{code, detail, weight}` (a suppressed
/// flag carries weight 0).
#[derive(Serialize)]
struct CiFlag {
    code: String,
    detail: String,
    weight: i32,
}

/// Mirrors Go's `ciFindingAdvisoryJSON` — same field order and `omitempty`
/// rules so the `ci --json` report is byte-parity with the reference.
#[derive(Serialize)]
struct CiAdvisory {
    id: String,
    severity: String,
    summary: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    url: String,
    source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    fixed_in: String,
    #[serde(skip_serializing_if = "is_zero_f64")]
    epss: f64,
    #[serde(skip_serializing_if = "is_zero_f64")]
    epss_percentile: f64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    in_kev: bool,
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

pub(crate) fn run_ci(
    file: &str,
    fail_on: &str,
    offline: bool,
    json: bool,
    sarif: bool,
) -> ExitCode {
    // fail-on is a VERDICT threshold (safe|review|prompt|block), matching Go.
    let Some(fail_on_v) = VerdictKind::parse(fail_on) else {
        eprintln!("aegis: unknown --fail-on verdict: {fail_on} (want safe|review|prompt|block)");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("aegis: cannot read {file}: {e}");
            return ExitCode::from(2);
        }
    };
    let path = Path::new(file);
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or(file);
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
    // Project name = the lockfile's parent dir (mirrors Go's project identity).
    let project = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("project")
        .to_string();

    // Advisories for every pinned dep (OSV + GHSA, EPSS/KEV enriched), unless
    // offline. Keyed by versioned_key.
    let queries: Vec<AdvisoryQuery> = deps
        .iter()
        .filter(|d| !d.version.is_empty())
        .map(|d| AdvisoryQuery {
            ecosystem: d.ecosystem,
            name: d.name.clone(),
            version: d.version.clone(),
        })
        .collect();
    let adv_map = if offline {
        std::collections::BTreeMap::new()
    } else {
        match advisories_by_key(&queries) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("aegis: advisory lookup failed: {e}");
                return ExitCode::from(2);
            }
        }
    };

    // Enrich (fetch source + AST/heuristics scan → per-dep verdict) unless
    // offline. Builtin allowlist applies during scoring, like Go.
    let enriched = !offline;
    let allow = match resolved_allow_set(Vec::new()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };

    // Per-dep enrich in parallel (each does its own network fetch).
    let mut findings: Vec<CiFinding> = deps
        .par_iter()
        .map(|d| {
            let assessment = if enriched {
                enrich_dep(d, &allow)
            } else {
                RiskAssessment::default()
            };
            let advs = adv_map.get(&d.versioned_key()).cloned().unwrap_or_default();
            let cap_v = verdict(&assessment, &RiskAssessment::default());
            let final_v = cap_v.max(verdict_for_advisories(&advs));
            CiFinding {
                ecosystem: d.ecosystem.as_str().to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
                direct: d.direct,
                verdict: final_v.name().to_string(),
                risk_score: assessment.score,
                // Suppressed (allowlisted) flags are omitted from the ci
                // finding, matching Go — they don't contribute to the score.
                flags: assessment
                    .flags
                    .iter()
                    .filter(|f| !f.suppressed)
                    .map(|f| CiFlag {
                        code: f.code.clone(),
                        detail: f.detail.clone(),
                        weight: f.weight,
                    })
                    .collect(),
                advisories: advs.iter().map(CiAdvisory::from).collect(),
            }
        })
        .collect();
    findings.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));

    // Summary tally over ALL deps; the reported findings are those whose
    // verdict meets the fail-on threshold.
    let mut summary = CiSummary {
        total: findings.len(),
        safe: 0,
        review: 0,
        prompt: 0,
        blocked: 0,
    };
    for f in &findings {
        match f.verdict.as_str() {
            "safe" => summary.safe += 1,
            "review" => summary.review += 1,
            "prompt" => summary.prompt += 1,
            "block" => summary.blocked += 1,
            _ => {}
        }
    }
    let gated: Vec<CiFinding> = findings
        .into_iter()
        .filter(|f| VerdictKind::parse(&f.verdict).is_some_and(|v| v >= fail_on_v))
        .collect();
    let passed = gated.is_empty();

    if sarif {
        // SARIF stays advisory-oriented (GitHub code-scanning surfaces CVEs).
        let adv_findings = advisory_finding_views(&deps, &adv_map);
        println!("{}", ci_findings_to_sarif(&adv_findings));
        return exit_for(passed);
    }
    if json {
        let report = CiReport {
            project,
            fail_on: fail_on_v.name().to_string(),
            enriched,
            passed,
            summary,
            findings: gated,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!(
            "project: {project} — {} deps ({} safe, {} review, {} prompt, {} blocked){}",
            summary.total,
            summary.safe,
            summary.review,
            summary.prompt,
            summary.blocked,
            if enriched { "" } else { " [offline]" }
        );
        for f in &gated {
            println!(
                "  [{}] {}/{}@{} (score {})",
                f.verdict, f.ecosystem, f.name, f.version, f.risk_score
            );
            for a in &f.advisories {
                println!("      {} [{}] {}", a.id, a.severity, a.summary);
            }
        }
        println!(
            "verdict: {} (fail-on {})",
            if passed { "pass" } else { "FAIL" },
            fail_on_v.name()
        );
    }
    exit_for(passed)
}

impl From<&Advisory> for CiAdvisory {
    fn from(a: &Advisory) -> Self {
        CiAdvisory {
            id: a.id.clone(),
            severity: a.severity.as_str().to_string(),
            summary: a.summary.clone(),
            url: a.url.clone(),
            source: a.source.clone(),
            fixed_in: a.fixed_in.clone(),
            epss: a.epss,
            epss_percentile: a.epss_percentile,
            in_kev: a.in_kev,
        }
    }
}

/// Flatten the per-dep advisory map into the flat [`FindingView`] list the
/// SARIF emitter consumes.
fn advisory_finding_views(
    deps: &[Dependency],
    adv_map: &std::collections::BTreeMap<String, Vec<Advisory>>,
) -> Vec<FindingView> {
    let mut out = Vec::new();
    for d in deps {
        let Some(advs) = adv_map.get(&d.versioned_key()) else {
            continue;
        };
        for a in advs {
            out.push(FindingView {
                ecosystem: d.ecosystem.as_str().to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
                advisory: a.id.clone(),
                severity: a.severity.as_str().to_string(),
                summary: a.summary.clone(),
                fixed_in: a.fixed_in.clone(),
                epss: a.epss,
                in_kev: a.in_kev,
            });
        }
    }
    out
}

fn exit_for(passed: bool) -> ExitCode {
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
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
    /// true when an allowlist rule excused this flag (weight not counted).
    suppressed: bool,
    /// the matching rule's reason; omitted when not suppressed.
    #[serde(skip_serializing_if = "String::is_empty")]
    suppress_by: String,
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
    /// User capability-suppression rules, merged on top of the builtin set.
    #[serde(default, rename = "allow")]
    allow: Vec<AllowRuleConfig>,
}

/// One `[[allow]]` config entry: an ecosystem/name/version/capability tuple
/// whose risk-flag contribution should be suppressed.
#[derive(Deserialize)]
struct AllowRuleConfig {
    #[serde(default = "crate::util::default_ecosystem")]
    ecosystem: String,
    /// Package name, or "*" for any package in the ecosystem.
    name: String,
    /// Semver range, or empty/"*" for any version.
    #[serde(default)]
    version_range: String,
    /// Capability slug (e.g. "dynamic-eval"); omit to suppress any capability.
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    reason: String,
}

/// Convert parsed config entries into domain [`AllowRule`]s, validating the
/// ecosystem and capability slugs. Source is stamped "user".
fn allow_rules_from_config(
    entries: &[AllowRuleConfig],
) -> Result<Vec<aegis_domain::AllowRule>, String> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let eco = parse_ecosystem(&e.ecosystem).ok_or_else(|| {
            format!(
                "allow rule {:?}: unknown ecosystem {:?}",
                e.name, e.ecosystem
            )
        })?;
        let capability = match &e.capability {
            Some(slug) if !slug.is_empty() => {
                Some(Capability::from_name(slug).ok_or_else(|| {
                    format!("allow rule {:?}: unknown capability {slug:?}", e.name)
                })?)
            }
            _ => None,
        };
        out.push(aegis_domain::AllowRule {
            ecosystem: eco,
            name: e.name.clone(),
            version_range: e.version_range.clone(),
            capability,
            reason: e.reason.clone(),
            source: "user".to_string(),
        });
    }
    Ok(out)
}

/// Compile the effective allowlist: the builtin rules plus `user` rules.
/// Builtin first so a user rule sharing a package can add coverage; matching
/// is OR-based, so any match suppresses.
fn resolved_allow_set(
    user: Vec<aegis_domain::AllowRule>,
) -> Result<aegis_domain::AllowSet, String> {
    let mut rules = builtin_allow_rules();
    rules.extend(user);
    aegis_domain::AllowSet::new(rules)
}

/// Load `[[allow]]` rules from a standalone TOML file (for `analyze
/// --allowlist`). The file uses the same `[[allow]]` shape as `aegis.toml`.
fn load_allow_file(path: &str) -> Result<Vec<aegis_domain::AllowRule>, String> {
    #[derive(Deserialize)]
    struct AllowFile {
        #[serde(default, rename = "allow")]
        allow: Vec<AllowRuleConfig>,
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let parsed: AllowFile = toml::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    allow_rules_from_config(&parsed.allow)
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
    /// Dependencies present in the lockfile but never imported in source, when
    /// the "unused-deps" check ran.
    #[serde(default)]
    unused_deps: Vec<String>,
    /// Retained risk flags from the source scan, for `run --sarif` aggregation.
    /// Not serialized to `--json` (which reports counts/verdict).
    #[serde(skip)]
    flags: Vec<TaskFlag>,
    failed: bool,
    error: Option<String>,
}

/// One risk flag on a task, kept for SARIF emission.
struct TaskFlag {
    code: String,
    detail: String,
    weight: i32,
    suppressed: bool,
}

#[derive(Serialize)]
struct RunView {
    failed: bool,
    tasks: Vec<TaskResult>,
}

/// Run one task: collect its files once, then run the checks it declares.
fn run_task(t: &TaskConfig, allow: &aegis_domain::AllowSet) -> TaskResult {
    let mut res = TaskResult {
        name: t.name.clone(),
        path: t.path.clone(),
        verdict: None,
        score: 0,
        cve_findings: 0,
        deprecated_findings: 0,
        license_findings: 0,
        unused_deps: Vec::new(),
        flags: Vec::new(),
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
        // Allowlist suppression: excuse capabilities declared expected for
        // this package (builtin + user rules). Version unknown here → "".
        let assessment = aegis_domain::apply_allowlist(&assessment, allow, eco, &t.name, "");
        let v = verdict(&assessment, &RiskAssessment::default());
        res.verdict = Some(v.name().to_string());
        res.score = assessment.score;
        res.flags = assessment
            .flags
            .iter()
            .map(|f| TaskFlag {
                code: f.code.clone(),
                detail: f.detail.clone(),
                weight: f.weight,
                suppressed: f.suppressed,
            })
            .collect();
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

    // Unused-dependency check: packages declared in package.json `dependencies`
    // but never imported in the task's JS/TS source are dead attack surface
    // (a barely-used dependency is exactly the event-stream vector). Reported,
    // not fail-by-default. Uses declared deps, not the lockfile — transitive
    // deps are legitimately not imported by the top-level source.
    if want("unused-deps") {
        if let Some(declared) = declared_npm_dependencies(&files) {
            let imported = aegis_reach::imported_dep_keys(&files);
            let mut unused: Vec<String> = declared
                .into_iter()
                .filter(|name| !imported.contains(name))
                .collect();
            unused.sort();
            unused.dedup();
            res.unused_deps = unused;
        }
    }

    res
}

/// The `dependencies` keys declared in a task's package.json (runtime deps
/// only). `None` if there's no package.json.
fn declared_npm_dependencies(files: &[(String, Vec<u8>)]) -> Option<Vec<String>> {
    let (_, raw) = files
        .iter()
        .find(|(rel, _)| rel.rsplit(['/', '\\']).next() == Some("package.json"))
        .map(|(rel, bytes)| (rel.as_str(), bytes.as_slice()))?;
    let manifest: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let deps = manifest.get("dependencies").and_then(|d| d.as_object())?;
    Some(deps.keys().cloned().collect())
}

pub(crate) fn run_config(config_path: &str, json: bool, sarif: bool) -> ExitCode {
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

    // Effective allowlist = builtin + config [[allow]] rules, applied to each
    // task's source-scan assessment.
    let allow = match allow_rules_from_config(&config.allow).and_then(resolved_allow_set) {
        Ok(set) => set,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };

    // Independent tasks run in PARALLEL (each task's source scan also fans out).
    let results: Vec<TaskResult> = config
        .tasks
        .par_iter()
        .map(|t| run_task(t, &allow))
        .collect();
    let failed = results.iter().any(|r| r.failed);

    if sarif {
        // One SARIF result per (task, flag); rules deduped by capability code;
        // logical location = the task's package identity.
        let mut seen_rules = std::collections::HashSet::new();
        let mut rules = Vec::new();
        let mut findings = Vec::new();
        for r in &results {
            let loc = format!("{}:{}", r.name, r.path);
            for f in &r.flags {
                if seen_rules.insert(f.code.clone()) {
                    rules.push(aegis_sbom::sarif::RuleDef {
                        id: f.code.clone(),
                        description: f.detail.clone(),
                        level: flag_level(f.weight).to_string(),
                    });
                }
                findings.push(aegis_sbom::sarif::FindingRef {
                    rule_id: f.code.clone(),
                    level: flag_level(f.weight).to_string(),
                    message: format!("{}: {}", r.name, f.detail),
                    location: Some(loc.clone()),
                    suppressed: f.suppressed,
                });
            }
        }
        println!(
            "{}",
            aegis_sbom::sarif::build_json(env!("CARGO_PKG_VERSION"), &rules, &findings)
        );
        return if failed {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }

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
                "[{status}] {} ({}) — verdict={verdict} score={} cve={} deprecated={} license={} unused={}",
                r.name,
                r.path,
                r.score,
                r.cve_findings,
                r.deprecated_findings,
                r.license_findings,
                r.unused_deps.len()
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

/// Map a risk-flag weight to a SARIF level (capabilities carry no severity, so
/// weight is the proxy: heavy → error, moderate → warning, light → note).
fn flag_level(weight: i32) -> &'static str {
    if weight >= 60 {
        "error"
    } else if weight >= 20 {
        "warning"
    } else {
        "note"
    }
}

pub(crate) fn run_analyze(
    dir: &str,
    name: Option<&str>,
    ecosystem: &str,
    online: bool,
    allowlist: Option<&str>,
    json: bool,
    sarif: bool,
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
    // Allowlist suppression (builtin + optional --allowlist file). Version is
    // unknown from a source dir → "", so only version-agnostic rules match.
    let user_rules = match allowlist {
        Some(path) => match load_allow_file(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("aegis: {e}");
                return ExitCode::from(2);
            }
        },
        None => Vec::new(),
    };
    match resolved_allow_set(user_rules) {
        Ok(set) => {
            assessment = aegis_domain::apply_allowlist(&assessment, &set, eco, &pkg_name, "");
        }
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    }
    let v = verdict(&assessment, &RiskAssessment::default());

    if sarif {
        let loc = format!("{}/{pkg_name}", eco.as_str());
        let rules: Vec<aegis_sbom::sarif::RuleDef> = assessment
            .flags
            .iter()
            .map(|f| aegis_sbom::sarif::RuleDef {
                id: f.code.clone(),
                description: f.detail.clone(),
                level: flag_level(f.weight).to_string(),
            })
            .collect();
        let findings: Vec<aegis_sbom::sarif::FindingRef> = assessment
            .flags
            .iter()
            .map(|f| aegis_sbom::sarif::FindingRef {
                rule_id: f.code.clone(),
                level: flag_level(f.weight).to_string(),
                message: f.detail.clone(),
                location: Some(loc.clone()),
                suppressed: f.suppressed,
            })
            .collect();
        println!(
            "{}",
            aegis_sbom::sarif::build_json(env!("CARGO_PKG_VERSION"), &rules, &findings)
        );
        return ExitCode::SUCCESS;
    }

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
                    suppressed: f.suppressed,
                    suppress_by: f.suppress_by.clone(),
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
                if f.suppressed {
                    println!(
                        "  [  0] {} — {} (suppressed: {})",
                        f.code, f.detail, f.suppress_by
                    );
                } else {
                    println!("  [{:>3}] {} — {}", f.weight, f.code, f.detail);
                }
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
    online: bool,
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
    let mut deps = match parse_file(basename, &bytes, &DirectMap::new()) {
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

    // --online: resolve each dep's SPDX license from its registry (rayon
    // over deps) and populate the license field the emitters read.
    if online {
        let fetcher = aegis_registry::LicenseFetcher::default();
        deps.par_iter_mut().for_each(|d| {
            let http = UreqClient::new();
            if let Some(lic) = fetcher.fetch_license(&http, d.ecosystem, &d.name, &d.version) {
                d.license = lic;
            }
        });
    }

    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let project = project.unwrap_or_default().to_string();
    let serial_number = serial.unwrap_or_default().to_string();

    // --online also resolves known advisories (OSV+GHSA, EPSS/KEV enriched)
    // into the SBOM vuln section. Offline → an empty map (no vuln section).
    let advisories = if online {
        let queries: Vec<AdvisoryQuery> = deps
            .iter()
            .filter(|d| !d.version.is_empty())
            .map(|d| AdvisoryQuery {
                ecosystem: d.ecosystem,
                name: d.name.clone(),
                version: d.version.clone(),
            })
            .collect();
        advisories_by_key(&queries).unwrap_or_default()
    } else {
        aegis_sbom::cyclonedx::AdvisoryMap::new()
    };

    let out = if fmt == "spdx" {
        aegis_sbom::spdx::build_json_adv(
            &deps,
            &advisories,
            &aegis_sbom::spdx::Options {
                aegis_version: version,
                project,
                timestamp,
                serial_number,
            },
        )
    } else {
        aegis_sbom::cyclonedx::build_json_adv(
            &deps,
            &advisories,
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
/// Resolve registry credentials: flags win, else the `AEGIS_REGISTRY_USER` /
/// `AEGIS_REGISTRY_PASS` env vars. Returns `None` when no username is present
/// (anonymous pull); a username with an empty password is still allowed
/// (some registries take a token as the username).
fn registry_credentials(
    username: Option<&str>,
    password: Option<&str>,
) -> Option<aegis_image::Credentials> {
    let user = username
        .map(str::to_string)
        .or_else(|| std::env::var("AEGIS_REGISTRY_USER").ok())
        .filter(|s| !s.is_empty())?;
    let pass = password
        .map(str::to_string)
        .or_else(|| std::env::var("AEGIS_REGISTRY_PASS").ok())
        .unwrap_or_default();
    Some(aegis_image::Credentials {
        username: user,
        password: pass,
    })
}

pub(crate) fn run_image(
    file: Option<&str>,
    reference: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    json: bool,
) -> ExitCode {
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
            // Credentials from flags, falling back to env. When neither is
            // set the pull stays anonymous (public images).
            let creds = registry_credentials(username, password);
            let result = match &creds {
                Some(c) => aegis_image::pull_image_auth(&client, r, Some(c)),
                None => aegis_image::pull_image(&client, r),
            };
            match result {
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
    /// Symbols of the package used in the project (function-level reachability).
    symbols: Vec<String>,
}

/// JSON view for a `reach --function` query: whether the symbol is used and,
/// when it is, the (file, function) sites that reach it.
#[derive(Serialize)]
struct ReachFunctionView {
    package: String,
    function: String,
    used: bool,
    callers: Vec<CallSiteView>,
}

/// One caller location in the `reach --function` JSON output.
#[derive(Serialize)]
struct CallSiteView {
    file: String,
    function: String,
    line: usize,
}

impl From<&aegis_reach::CallSite> for CallSiteView {
    fn from(c: &aegis_reach::CallSite) -> Self {
        CallSiteView {
            file: c.file.clone(),
            function: c.function.clone(),
            line: c.line,
        }
    }
}

/// JSON view for `reach --function --transitive`: the direct users plus the
/// call-graph callers that reach the symbol.
#[derive(Serialize)]
struct ReachTransitiveView {
    package: String,
    function: String,
    used: bool,
    transitive: bool,
    reaching: Vec<ReachEntryView>,
}

/// One reaching function in the transitive JSON output. `direct` = uses the
/// symbol itself; otherwise it only calls (directly or indirectly) one that
/// does, and `line` is 0.
#[derive(Serialize)]
struct ReachEntryView {
    file: String,
    function: String,
    line: usize,
    direct: bool,
}

impl From<&aegis_reach::ReachEntry> for ReachEntryView {
    fn from(e: &aegis_reach::ReachEntry) -> Self {
        ReachEntryView {
            file: e.file.clone(),
            function: e.function.clone(),
            line: e.line,
            direct: e.direct,
        }
    }
}

/// Report whether `package` is imported anywhere in the project's JS/TS source
/// (reachability). Exit 0 = reachable (used), 1 = unreachable (unused code the
/// risk engine can downgrade), 2 = not a directory.
pub(crate) fn run_reach(
    dir: &str,
    package: &str,
    function: Option<&str>,
    transitive: bool,
    json: bool,
) -> ExitCode {
    let root = Path::new(dir);
    if !root.is_dir() {
        eprintln!("aegis: not a directory: {dir}");
        return ExitCode::from(2);
    }
    let files = collect_files(root);

    // Function-level query: is this specific symbol of the package used? This
    // is advisory reachability — an advisory on an unused function is moot.
    if let Some(func) = function {
        let used = aegis_reach::used_symbols_of(package, &files).contains(func);

        // --transitive: also walk call-graph callers (cross-file, name-based).
        // Additive over the direct view; never narrows the `used` verdict.
        if transitive {
            let reaching = if used {
                aegis_reach::functions_reaching_transitive(package, func, &files)
            } else {
                Vec::new()
            };
            if json {
                let view = ReachTransitiveView {
                    package: package.to_string(),
                    function: func.to_string(),
                    used,
                    transitive: true,
                    reaching: reaching.iter().map(ReachEntryView::from).collect(),
                };
                match serde_json::to_string_pretty(&view) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("aegis: json encode failed: {e}");
                        return ExitCode::from(2);
                    }
                }
            } else if used {
                println!("{package}.{func}: used (advisory on this function is reachable)");
                for e in &reaching {
                    if e.direct {
                        println!("  ↳ {}:{} {} (direct)", e.file, e.line, e.function);
                    } else {
                        println!("  ↳ {} {} (transitive)", e.file, e.function);
                    }
                }
            } else {
                println!("{package}.{func}: not used (advisory on this function is unreachable)");
            }
            return if used {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }

        // Direct caller detail only (default): which project functions
        // reference the symbol themselves.
        let callers = if used {
            aegis_reach::functions_reaching(package, func, &files)
        } else {
            Vec::new()
        };
        if json {
            let view = ReachFunctionView {
                package: package.to_string(),
                function: func.to_string(),
                used,
                callers: callers.iter().map(CallSiteView::from).collect(),
            };
            match serde_json::to_string_pretty(&view) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("aegis: json encode failed: {e}");
                    return ExitCode::from(2);
                }
            }
        } else if used {
            println!("{package}.{func}: used (advisory on this function is reachable)");
            for c in &callers {
                println!("  ↳ {}:{} {}", c.file, c.line, c.function);
            }
        } else {
            println!("{package}.{func}: not used (advisory on this function is unreachable)");
        }
        return if used {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    let reach = aegis_reach::reachability_of(package, &files);
    let reachable = matches!(reach, aegis_domain::Reachability::Used);
    // When reachable, list which of the package's symbols the project uses —
    // the function-level detail for judging a function-scoped advisory.
    let mut symbols: Vec<String> = if reachable {
        aegis_reach::used_symbols_of(package, &files)
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    symbols.sort();

    if json {
        let view = ReachView {
            package: package.to_string(),
            reachable,
            reachability: format!("{reach:?}").to_lowercase(),
            symbols,
        };
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else if reachable {
        if symbols.is_empty() {
            println!("{package}: reachable (imported in project source)");
        } else {
            println!("{package}: reachable — uses: {}", symbols.join(", "));
        }
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
  aegis ci "$lock" --fail-on block || {
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
        run: aegis ci package-lock.json --fail-on block --sarif > aegis.sarif
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
