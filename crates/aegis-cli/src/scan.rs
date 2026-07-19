//! Source-scanning helpers: file collection, AST + heuristics scanning,
//! manifest normalization, online enrichment, and lockfile dep extraction.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use aegis_ast::{scanner_for, Findings, LanguageScanner};
use aegis_domain::{
    risk_score, Capability, CapabilitySet, Dependency, Ecosystem, Fingerprint, HookPhase,
    InstallHook, RiskAssessment,
};
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

    // Carry declared install hooks into the fingerprint so risk_score adds the
    // base `install-hook` flag (weight 30) and surfaces `install-hook-exec` —
    // the heuristics only flag a *suspicious* hook, not the declaration itself.
    // (Matches the Go analyzer, which scores both.)
    let hooks = to_install_hooks(&normalized.hooks);
    if !hooks.is_empty() {
        caps.push(Capability::InstallHookExec);
    }

    let fp = Fingerprint {
        analyzed: true,
        capabilities: CapabilitySet::new(caps),
        env_reads: findings.env_reads().to_vec(),
        source_size_bytes: source_bytes,
        hooks,
    };
    let assessment = risk_score(Some(&fp));
    (fp.capabilities, assessment)
}

/// Directories that hold dependency installs or build output, not user
/// source. Walking into them would mark transitive deps as "used" via *their*
/// imports, defeating the reachability layer. Mirrors Go's `SkipDirs`.
const REACH_SKIP_DIRS: &[&str] = &[
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".bundle",
    ".gradle",
    ".idea",
    ".vscode",
];

/// Per-ecosystem set of dependency keys imported by the project's own source,
/// used to classify each dep as reachable (Used) or not (Unused) for the `ci`
/// reachability downgrade. Built by [`project_reachability`].
pub(crate) struct ProjectReach {
    imported: HashMap<Ecosystem, std::collections::HashSet<String>>,
}

impl ProjectReach {
    /// Classify a dependency. `Used` when the project source imports it,
    /// otherwise `Unused` — matching Go's observed `ci` contract (a dep in a
    /// scanned lockfile that no source imports is Unused, never Unknown). Go
    /// import paths sit under a module root, so match by prefix there.
    pub(crate) fn classify(&self, dep: &Dependency) -> aegis_domain::Reachability {
        use aegis_domain::Reachability;
        let Some(keys) = self.imported.get(&dep.ecosystem) else {
            return Reachability::Unused;
        };
        if keys.contains(&dep.name) {
            return Reachability::Used;
        }
        if dep.ecosystem == Ecosystem::Go {
            let prefix = format!("{}/", dep.name);
            if keys.iter().any(|k| k.starts_with(&prefix)) {
                return Reachability::Used;
            }
        }
        Reachability::Unused
    }
}

/// Walk the project directory (skipping dependency/build dirs) and build a
/// per-ecosystem import index from its source files. Mirrors Go's
/// `AnalyzeUsage` + `WalkProject`. Bounded like [`collect_files`].
pub(crate) fn project_reachability(project_dir: &Path) -> ProjectReach {
    const MAX_FILES: usize = 20_000;
    const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
    let mut imported: HashMap<Ecosystem, std::collections::HashSet<String>> = HashMap::new();
    let mut count = 0usize;
    let mut stack = vec![project_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if count >= MAX_FILES {
                return ProjectReach { imported };
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if !REACH_SKIP_DIRS.contains(&name) {
                    stack.push(path);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let name = path.to_string_lossy();
            let Some(lang) = aegis_reach::language_for_path(&name) else {
                continue;
            };
            let Some(eco) = eco_for_reach_lang(lang) else {
                continue;
            };
            let too_big = entry
                .metadata()
                .map(|m| m.len() > MAX_FILE_BYTES)
                .unwrap_or(true);
            if too_big {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            count += 1;
            let bucket = imported.entry(eco).or_default();
            for imp in aegis_reach::extract_with(lang, &bytes) {
                if !imp.dep_key.is_empty() {
                    bucket.insert(imp.dep_key);
                }
            }
        }
    }
    ProjectReach { imported }
}

/// Map a reach grammar to its lockfile ecosystem. Mirrors Go's
/// `EcosystemForLanguage` for the languages the reach crate supports.
fn eco_for_reach_lang(lang: aegis_reach::Language) -> Option<Ecosystem> {
    use aegis_reach::Language;
    Some(match lang {
        Language::JavaScript => Ecosystem::Npm,
        Language::Python => Ecosystem::PyPI,
        Language::Go => Ecosystem::Go,
        Language::Php => Ecosystem::Packagist,
        Language::Ruby => Ecosystem::RubyGems,
    })
}

/// Ecosystems whose published source `enrich_dep` can fetch + capability-scan.
/// The reachability layer keys off this set (only enriched ecosystems get a
/// Used/Unused classification). npm/pypi/crates today.
pub(crate) fn is_enriched_ecosystem(eco: Ecosystem) -> bool {
    matches!(
        eco,
        Ecosystem::Npm | Ecosystem::PyPI | Ecosystem::Crates | Ecosystem::RubyGems | Ecosystem::Go
    )
}

/// Ecosystems the `ci` reachability layer can classify: enriched AND covered
/// by an aegis-reach import parser (js/python/go/ruby). Crates is enriched but
/// has no Rust import parser, so a crate dep stays Unknown (never downgraded on
/// a false "unused"). Go v0.29 classifies npm only — extending to the other
/// parseable enriched ecosystems is a Rust-ahead behavior.
pub(crate) fn reachability_eligible(eco: Ecosystem) -> bool {
    matches!(
        eco,
        Ecosystem::Npm | Ecosystem::PyPI | Ecosystem::Go | Ecosystem::RubyGems
    )
}

/// Fetch a dependency's published source from its registry. Returns the file
/// map (relative path, bytes) or an `Err` for ecosystems without a fetcher /
/// on any transport failure.
fn fetch_source(
    http: &dyn aegis_net::HttpClient,
    dep: &Dependency,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    match dep.ecosystem {
        Ecosystem::Npm => aegis_registry::fetch_npm_source(
            http,
            "https://registry.npmjs.org",
            &dep.name,
            &dep.version,
        ),
        Ecosystem::PyPI => {
            aegis_registry::fetch_pypi_source(http, "https://pypi.org", &dep.name, &dep.version)
        }
        Ecosystem::Crates => {
            aegis_registry::fetch_crates_source(http, "https://crates.io", &dep.name, &dep.version)
        }
        Ecosystem::RubyGems => aegis_registry::fetch_rubygems_source(
            http,
            "https://rubygems.org",
            &dep.name,
            &dep.version,
        ),
        Ecosystem::Go => aegis_registry::fetch_go_source(
            http,
            "https://proxy.golang.org",
            &dep.name,
            &dep.version,
        ),
        _ => Err("pkgsource: no fetcher for ecosystem".to_string()),
    }
}

/// Enrich one dependency for `ci`: fetch its published source, AST + heuristics
/// scan it, apply the allowlist, and return the capability risk assessment
/// (flags + score). Mirrors Go's per-dep snapshot enrich, extended past Go to
/// npm + pypi + crates (Go v0.29 fetches npm only).
///
/// Ecosystems without a fetcher — or any fetch/scan failure — return an empty
/// assessment (no capability signal; they still score via advisories in the
/// caller) so one bad dep never fails the whole run.
pub(crate) fn enrich_dep(dep: &Dependency, allow: &aegis_domain::AllowSet) -> RiskAssessment {
    if !is_enriched_ecosystem(dep.ecosystem) || dep.name.is_empty() || dep.version.is_empty() {
        return RiskAssessment::default();
    }
    let http = UreqClient::new();
    let files = match fetch_source(&http, dep) {
        Ok(f) => f,
        Err(_) => return RiskAssessment::default(),
    };
    let (_caps, assessment) = scan_source(&files, &dep.name, dep.ecosystem, Vec::new());
    aegis_domain::apply_allowlist(&assessment, allow, dep.ecosystem, &dep.name, &dep.version)
}

/// Map the heuristics' manifest hooks onto domain [`InstallHook`]s. Phase
/// strings mirror the Go npm parser (preinstall → PreInstall; install /
/// postinstall / prepare → PostInstall; build → Build). `source` is
/// `scripts.<phase>`. `sha256` is left empty — it's only consumed by snapshot
/// hook-drift, which `analyze` doesn't exercise.
fn to_install_hooks(hooks: &[aegis_heuristics::Hook]) -> Vec<InstallHook> {
    hooks
        .iter()
        .map(|h| {
            let phase = match h.phase.as_str() {
                "preinstall" => HookPhase::PreInstall,
                "build" => HookPhase::Build,
                _ => HookPhase::PostInstall,
            };
            InstallHook {
                phase,
                source: format!("scripts.{}", h.phase),
                sha256: String::new(),
            }
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_domain::Reachability;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn dep(name: &str, eco: Ecosystem) -> Dependency {
        Dependency {
            ecosystem: eco,
            name: name.to_string(),
            version: String::new(),
            integrity: String::new(),
            direct: false,
            depends_on: Vec::new(),
            provenance_status: String::new(),
            license: String::new(),
        }
    }

    fn scratch() -> std::path::PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "aegis-reach-ut-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn imported_dep_is_used_others_unused() {
        let dir = scratch();
        std::fs::write(
            dir.join("index.js"),
            b"const _ = require('lodash');\n_.merge({}, {});\n",
        )
        .unwrap();
        let reach = project_reachability(&dir);
        assert_eq!(
            reach.classify(&dep("lodash", Ecosystem::Npm)),
            Reachability::Used
        );
        // A dep the source never imports is Unused (not Unknown) — matches Go's
        // ci contract for a scanned lockfile.
        assert_eq!(
            reach.classify(&dep("left-pad", Ecosystem::Npm)),
            Reachability::Unused
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bare_project_marks_all_unused() {
        // No source files at all → nothing imported → every dep Unused.
        let dir = scratch();
        let reach = project_reachability(&dir);
        assert_eq!(
            reach.classify(&dep("lodash", Ecosystem::Npm)),
            Reachability::Unused
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_modules_is_skipped() {
        // An import living under node_modules must not count as project usage.
        let dir = scratch();
        let nm = dir.join("node_modules").join("foo");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("index.js"), b"require('lodash');\n").unwrap();
        let reach = project_reachability(&dir);
        assert_eq!(
            reach.classify(&dep("lodash", Ecosystem::Npm)),
            Reachability::Unused
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
