//! Source-scanning helpers: file collection, AST + heuristics scanning,
//! manifest normalization, online enrichment, and lockfile dep extraction.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use aegis_ast::{scanner_for, Findings, LanguageScanner};
use aegis_domain::{risk_score, CapabilitySet, Dependency, Ecosystem, Fingerprint, RiskAssessment};
use aegis_heuristics::go_retract::parse_go_retract;
use aegis_heuristics::manifest::parse_npm_manifest;
use aegis_heuristics::{run_heuristics, NormalizedPackage};
use aegis_lockfile::{parse_file, DirectMap};
use aegis_net::UreqClient;
use rayon::prelude::*;

/// Recursively collect `(relative_path, bytes)` for regular files under
/// `root`. Bounded so a pathological tree can't exhaust memory.
pub(crate) fn collect_files(root: &Path) -> Vec<(String, Vec<u8>)> {
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

/// Scan a package's source files (AST — PARALLEL across cores — + heuristics)
/// and return the risk assessment. Shared by `analyze` and the config runner.
pub(crate) fn scan_source(
    files: &[(String, Vec<u8>)],
    pkg_name: &str,
    eco: Ecosystem,
    extra_caps: Vec<aegis_domain::Capability>,
) -> (CapabilitySet, RiskAssessment) {
    // Compile one scanner per distinct extension once; share it read-only
    // across the rayon pool; scan every file concurrently; merge.
    let mut scanners: HashMap<String, Option<Arc<dyn LanguageScanner>>> = HashMap::new();
    for (rel, _) in files {
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
        .reduce(Findings::default, |mut a, b| {
            a.merge(b);
            a
        });

    // Heuristics over the whole file set. Enrich the package from its manifest
    // so the metadata detectors (vcs-dep, install-hook, unlisted-payload,
    // go-retract) have Deps / Hooks / retract data, not just raw files.
    let normalized = build_normalized(files, pkg_name, eco);
    let mut caps = findings.capabilities();
    caps.extend(run_heuristics(&normalized));
    caps.extend(extra_caps);

    let fp = Fingerprint {
        analyzed: true,
        capabilities: CapabilitySet::new(caps),
        env_reads: findings.env_reads().to_vec(),
        source_size_bytes: source_bytes,
        ..Default::default()
    };
    let assessment = risk_score(Some(&fp));
    (fp.capabilities, assessment)
}

/// Build the heuristics view of a package: always the raw file set, plus
/// ecosystem-specific manifest enrichment (npm package.json → deps + hooks;
/// go.mod → retract list) so the metadata detectors get structured input, not
/// just files. `analyze` runs on a source tree with no pinned version, so the
/// go-retract check stays dormant (needs `version`) — the parser still runs.
fn build_normalized(
    files: &[(String, Vec<u8>)],
    pkg_name: &str,
    eco: Ecosystem,
) -> NormalizedPackage {
    let file_map: HashMap<String, Vec<u8>> =
        files.iter().map(|(r, b)| (r.clone(), b.clone())).collect();

    match eco {
        Ecosystem::Npm => {
            if let Some((_, raw)) = find_manifest(files, "package.json") {
                return parse_npm_manifest(pkg_name, raw, file_map);
            }
        }
        Ecosystem::Go => {
            let mut pkg = NormalizedPackage::new(pkg_name, eco);
            pkg.files = file_map;
            if let Some((_, raw)) = find_manifest(files, "go.mod") {
                let (versions, ranges) = parse_go_retract(&String::from_utf8_lossy(raw));
                pkg.retracted_versions = versions;
                pkg.retracted_ranges = ranges;
                pkg.manifest_raw = raw.to_vec();
            }
            return pkg;
        }
        _ => {}
    }

    let mut pkg = NormalizedPackage::new(pkg_name, eco);
    pkg.files = file_map;
    pkg
}

/// Find the manifest whose basename is `name`, preferring the shallowest path
/// (the package root) so a nested fixture doesn't shadow the top-level one.
fn find_manifest<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> Option<(&'a str, &'a [u8])> {
    files
        .iter()
        .filter(|(rel, _)| rel.rsplit('/').next() == Some(name))
        .min_by_key(|(rel, _)| rel.matches('/').count())
        .map(|(rel, bytes)| (rel.as_str(), bytes.as_slice()))
}

/// Network checks for `analyze --online` (npm only): the maintainer-hijack
/// signal (packument) and tarball-drift (local tree vs the upstream GitHub tag).
/// Best-effort — anything unresolvable (offline, 404, non-npm, non-GitHub repo,
/// rate-limit) contributes no capabilities. Reads name/version/repository from
/// package.json.
pub(crate) fn fetch_online_caps(
    files: &[(String, Vec<u8>)],
    pkg_name: &str,
    eco: Ecosystem,
) -> Vec<aegis_domain::Capability> {
    if eco != Ecosystem::Npm {
        return Vec::new();
    }
    let Some((_, raw)) = find_manifest(files, "package.json") else {
        return Vec::new();
    };
    let manifest: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(pkg_name);
    let Some(version) = manifest.get("version").and_then(|v| v.as_str()) else {
        return Vec::new();
    };
    if name.is_empty() || version.is_empty() {
        return Vec::new();
    }

    let client = UreqClient::new();
    let mut caps = Vec::new();

    // 1. Maintainer-hijack signal from the npm packument.
    let sig = aegis_registry::fetch_maintainer_signal(
        &client,
        aegis_registry::npm::DEFAULT_REGISTRY_URL,
        aegis_registry::npm::DEFAULT_DOWNLOADS_URL,
        name,
        version,
    );
    // Copy the registry signal into the heuristics signal (decoupled crates).
    let hsig = aegis_heuristics::maintainer::MaintainerSignal {
        published_at: sig.published_at,
        weekly_downloads: sig.weekly_downloads,
        previous_version: sig.previous_version,
        previous_published_at: sig.previous_published_at,
        publisher: sig.publisher,
        previous_publisher: sig.previous_publisher,
        version_unpublished: sig.version_unpublished,
    };
    caps.extend(aegis_heuristics::maintainer::check_maintainer_now(&hsig));

    // 2. Tarball-drift: local tree vs the upstream GitHub tag for this version.
    if let Some(repo) = repository_url(&manifest) {
        let token = std::env::var("GITHUB_TOKEN").ok();
        if let Some(repo_files) = aegis_registry::github::fetch_repo_files(
            &client,
            aegis_registry::github::DEFAULT_GITHUB_API,
            token.as_deref(),
            &repo,
            name,
            version,
        ) {
            let normalized = build_normalized(files, name, eco);
            caps.extend(aegis_heuristics::tarball_drift::check_tarball_drift(
                &normalized,
                &repo_files,
                "",
            ));
        }
    }

    caps
}

/// Fetch the npm SLSA provenance attestation for this package; when it's
/// missing, return the `provenance-missing` risk flag. npm-only, best-effort:
/// any failure (offline, non-npm, no name/version, registry error) → `None`.
pub(crate) fn provenance_flag(
    files: &[(String, Vec<u8>)],
    pkg_name: &str,
    eco: Ecosystem,
) -> Option<aegis_domain::RiskFlag> {
    if eco != Ecosystem::Npm {
        return None;
    }
    let (_, raw) = find_manifest(files, "package.json")?;
    let manifest: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(pkg_name);
    let version = manifest.get("version").and_then(|v| v.as_str())?;
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let client = UreqClient::new();
    let status = aegis_registry::fetch_provenance(
        &client,
        aegis_registry::attestations::DEFAULT_REGISTRY_URL,
        name,
        version,
    );
    if status.has_provenance {
        return None;
    }
    // No attestation → flag it via the domain rule.
    let dep = Dependency {
        ecosystem: Ecosystem::Npm,
        name: name.to_string(),
        version: version.to_string(),
        provenance_status: "missing".to_string(),
        ..Default::default()
    };
    aegis_domain::provenance_risk_flag(&dep)
}

/// Pull the `repository` URL/shorthand out of a package.json (string form or
/// `{ "url": ... }` object form).
fn repository_url(manifest: &serde_json::Value) -> Option<String> {
    let repo = manifest.get("repository")?;
    if let Some(s) = repo.as_str() {
        return Some(s.to_string());
    }
    repo.get("url").and_then(|u| u.as_str()).map(str::to_string)
}

/// Parse every lockfile in a task's file set into its dependency list.
/// Dispatches by basename; non-lockfiles and parse failures are skipped.
pub(crate) fn lockfile_deps(files: &[(String, Vec<u8>)]) -> Vec<Dependency> {
    let mut out = Vec::new();
    for (rel, bytes) in files {
        let base = rel.rsplit(['/', '\\']).next().unwrap_or(rel);
        if let Ok(Some(deps)) = parse_file(base, bytes, &DirectMap::new()) {
            out.extend(deps);
        }
    }
    out
}
