//! Tarball-drift detector. Port of `internal/infra/scan/drift/diff.go` (the
//! pure diff engine) + `tarball_drift.go` (the confidence-cutoff wrapper).
//!
//! Compares the published tarball's file list against the upstream repo's git
//! tree. Paths present in the tarball but missing from the repo — and not
//! covered by the build-output / package.json-`files` whitelist — are drift:
//! code smuggled in at publish time. Fires [`Capability::TarballDrift`].
//!
//! Pure: no I/O. The GitHub-tree fetch that produces `repo_files` lives in the
//! network layer (not yet ported); an empty `repo_files` is "no signal", not
//! "no drift", so the detector is dormant until that fetch is wired.

use aegis_domain::Capability;

use crate::manifest::extract_package_files_field;
use crate::NormalizedPackage;

/// One tarball path missing from the upstream repo and not whitelisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftEvidence {
    /// Tarball-relative path (npm "package/" prefix already stripped).
    pub path: String,
    /// Why it crossed the threshold: "script-file", "code-file", "binary-file".
    pub reason: String,
}

/// Everything the pure diff needs. Empty `tarball_files` or `repo_files` → no
/// result.
#[derive(Debug, Default)]
pub struct DiffInputs {
    /// Tarball file list, leading "package/" segment already stripped.
    pub tarball_files: Vec<String>,
    /// Repo git-tree file list, relative to repo root.
    pub repo_files: Vec<String>,
    /// The package.json `files` field — matched globs are expected artifacts.
    pub package_json_files: Vec<String>,
    /// Install-hook phase → raw script body. Paths referenced here that are
    /// missing from the repo are the highest-signal shape.
    pub hook_scripts: Vec<(String, String)>,
    /// Monorepo subdir the package was published from, e.g. "packages/core".
    pub repo_subdir: String,
}

const BUILD_OUTPUT_DIRS: &[&str] = &[
    "dist/", "lib/", "build/", "out/", "cjs/", "mjs/", "esm/", "umd/", "types/", "typings/", "dts/",
];
const METADATA_LITERALS: &[&str] = &[
    "package.json",
    "readme.md",
    "readme",
    "license",
    "license.md",
    "license.txt",
    "changelog.md",
    "changelog",
    "notice",
    "authors",
    "contributors.md",
];
const CODE_EXTENSIONS: &[&str] = &[
    "js", "cjs", "mjs", "jsx", "ts", "tsx", "json", "sh", "bat", "ps1",
];
const BINARY_ARTIFACTS: &[&str] = &["node", "so", "dll", "dylib", "wasm", "exe"];

/// Return the tarball paths that don't exist in the upstream repo and don't
/// match the whitelist. Sorted by path for a stable, hashable result. Pure.
pub fn diff(inputs: &DiffInputs) -> Vec<DriftEvidence> {
    if inputs.tarball_files.is_empty() || inputs.repo_files.is_empty() {
        return Vec::new();
    }

    let subdir = inputs.repo_subdir.trim_matches('/');
    let mut repo_set: Vec<String> = Vec::with_capacity(inputs.repo_files.len());
    for p in &inputs.repo_files {
        let p = p.trim_start_matches("./").trim_matches('/');
        let p = if subdir.is_empty() {
            p
        } else {
            match p.strip_prefix(&format!("{subdir}/")) {
                Some(rest) => rest,
                None => continue,
            }
        };
        repo_set.push(p.to_ascii_lowercase());
    }

    let hook_files = extract_hook_script_paths(&inputs.hook_scripts);
    let whitelist = Whitelist::build(&inputs.package_json_files);

    let mut out: Vec<DriftEvidence> = Vec::new();
    for raw in &inputs.tarball_files {
        let clean = raw.trim_start_matches("./").trim_matches('/');
        if clean.is_empty() || raw.ends_with('/') {
            continue;
        }
        let lower = clean.to_ascii_lowercase();
        if repo_set.contains(&lower) {
            continue;
        }
        if hook_files.contains(&lower) {
            out.push(DriftEvidence {
                path: clean.to_string(),
                reason: "script-file".to_string(),
            });
            continue;
        }
        if whitelist.accepts(clean) {
            continue;
        }
        if is_code_file(clean) {
            out.push(DriftEvidence {
                path: clean.to_string(),
                reason: "code-file".to_string(),
            });
            continue;
        }
        if is_binary_artifact(clean) {
            out.push(DriftEvidence {
                path: clean.to_string(),
                reason: "binary-file".to_string(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

struct Whitelist {
    prefixes: Vec<String>,
    literals: Vec<String>,
    globs: Vec<String>,
}

impl Whitelist {
    fn build(pkg_files: &[String]) -> Self {
        let mut prefixes: Vec<String> = BUILD_OUTPUT_DIRS.iter().map(|s| s.to_string()).collect();
        let mut literals: Vec<String> = METADATA_LITERALS.iter().map(|s| s.to_string()).collect();
        let mut globs = Vec::new();
        for p in pkg_files {
            let p = p.trim().trim_start_matches("./").trim_matches('/');
            if p.is_empty() {
                continue;
            }
            if p.contains('*') || p.contains('?') {
                globs.push(p.to_string());
                continue;
            }
            prefixes.push(format!("{}/", p.to_ascii_lowercase()));
            literals.push(p.to_ascii_lowercase());
        }
        Whitelist {
            prefixes,
            literals,
            globs,
        }
    }

    fn accepts(&self, p: &str) -> bool {
        let lp = p.to_ascii_lowercase();
        if self.literals.contains(&lp) {
            return true;
        }
        let base = lp.rsplit('/').next().unwrap_or(&lp);
        if METADATA_LITERALS.contains(&base) {
            return true;
        }
        if self.prefixes.iter().any(|pref| lp.starts_with(pref)) {
            return true;
        }
        self.globs.iter().any(|g| match_simple_glob(g, p))
    }
}

/// Minimal glob: `*` matches any run of non-`/` chars, `**` collapses to `*`,
/// everything else is literal (case-insensitive). Sufficient for npm `files`.
fn match_simple_glob(pattern: &str, name: &str) -> bool {
    let pat = pattern.replace("**", "*").to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    match_glob_segments(pat.as_bytes(), name.as_bytes())
}

fn match_glob_segments(pat: &[u8], s: &[u8]) -> bool {
    if pat.is_empty() {
        return s.is_empty();
    }
    if pat[0] == b'*' {
        let rest = &pat[1..];
        // '*' matches zero+ chars but never crosses a '/'.
        for i in 0..=s.len() {
            if i > 0 && s[i - 1] == b'/' {
                break;
            }
            if match_glob_segments(rest, &s[i..]) {
                return true;
            }
        }
        return false;
    }
    if s.is_empty() || pat[0] != s[0] {
        return false;
    }
    match_glob_segments(&pat[1..], &s[1..])
}

fn ext_of(p: &str) -> String {
    let base = p.rsplit('/').next().unwrap_or(p);
    base.rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_code_file(p: &str) -> bool {
    CODE_EXTENSIONS.contains(&ext_of(p).as_str())
}
fn is_binary_artifact(p: &str) -> bool {
    BINARY_ARTIFACTS.contains(&ext_of(p).as_str())
}

/// Pull relative file paths referenced in install-hook script bodies.
/// Deliberately lax: any token that looks like a file path (has a dir sep or
/// an extension, isn't a flag or URL) counts. Over-matching here is safe — a
/// path only matters when it's also absent from the repo.
fn extract_hook_script_paths(hooks: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (_, body) in hooks {
        for tok in tokenize_shell(body) {
            let tok = tok.trim_start_matches("./");
            if !tok.contains('/') && !tok.contains('.') {
                continue;
            }
            if tok.starts_with('-') || tok.contains("://") {
                continue;
            }
            if ext_of(tok).is_empty() {
                continue;
            }
            out.push(tok.to_ascii_lowercase());
        }
    }
    out
}

fn tokenize_shell(body: &str) -> Vec<String> {
    body.split([' ', '\t', '\n', ';', '|', '&', '(', ')', '`'])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

// --- wrapper: confidence cutoff over the raw diff ---------------------------

const SMALL_DRIFT_CUTOFF: usize = 4;
const RATIO_THRESHOLD: f64 = 0.30;

fn has_script_file_evidence(ev: &[DriftEvidence]) -> bool {
    ev.iter().any(|e| e.reason == "script-file")
}

/// True when the drift count is large enough relative to the tarball that the
/// likely cause is "compared against the wrong monorepo subdir", not real
/// payload. Small absolute drift (≤4) is always real signal.
fn is_likely_monorepo_subdir_mismatch(ev: &[DriftEvidence], tarball_files: &[String]) -> bool {
    if ev.len() <= SMALL_DRIFT_CUTOFF {
        return false;
    }
    let considered = tarball_files
        .iter()
        .filter(|p| {
            matches!(
                ext_of(p).as_str(),
                "js" | "mjs" | "cjs" | "ts" | "json" | "node" | "so" | "wasm"
            )
        })
        .count();
    if considered == 0 {
        return false;
    }
    ev.len() as f64 / considered as f64 > RATIO_THRESHOLD
}

/// Run the drift diff and apply the confidence cutoff, returning the capability
/// plus its evidence. Script-file evidence always fires (robust to subdir
/// mismatch); otherwise a wholesale mismatch is suppressed as a likely
/// wrong-subdir comparison.
pub fn detect_tarball_drift(inputs: &DiffInputs) -> Option<(Capability, Vec<DriftEvidence>)> {
    let ev = diff(inputs);
    if ev.is_empty() {
        return None;
    }
    if has_script_file_evidence(&ev) {
        return Some((Capability::TarballDrift, ev));
    }
    if is_likely_monorepo_subdir_mismatch(&ev, &inputs.tarball_files) {
        return None;
    }
    Some((Capability::TarballDrift, ev))
}

/// Convenience over a [`NormalizedPackage`] + upstream repo file list: pulls
/// the tarball file list, package.json `files`, and install hooks off the
/// package and runs [`detect_tarball_drift`]. Returns just the capability for
/// the run_heuristics-style flow.
pub fn check_tarball_drift(
    pkg: &NormalizedPackage,
    repo_files: &[String],
    repo_subdir: &str,
) -> Vec<Capability> {
    if repo_files.is_empty() || pkg.files.is_empty() {
        return Vec::new();
    }
    let inputs = DiffInputs {
        tarball_files: pkg.files.keys().cloned().collect(),
        repo_files: repo_files.to_vec(),
        package_json_files: extract_package_files_field(&pkg.manifest_raw),
        hook_scripts: pkg
            .hooks
            .iter()
            .map(|h| (h.phase.clone(), h.body.clone()))
            .collect(),
        repo_subdir: repo_subdir.to_string(),
    };
    match detect_tarball_drift(&inputs) {
        Some((cap, _)) => vec![cap],
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn di(tarball: &[&str], repo: &[&str]) -> DiffInputs {
        DiffInputs {
            tarball_files: tarball.iter().map(|s| s.to_string()).collect(),
            repo_files: repo.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_lodash_like_no_drift() {
        let got = diff(&di(
            &[
                "package.json",
                "README.md",
                "LICENSE",
                "src/index.js",
                "dist/index.js",
                "dist/index.cjs",
                "dist/index.d.ts",
            ],
            &["package.json", "README.md", "LICENSE", "src/index.js"],
        ));
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn drifted_extra_script_file() {
        let mut inputs = di(
            &["package.json", "index.js", "install.js"],
            &["package.json", "index.js"],
        );
        inputs.hook_scripts = vec![("postinstall".into(), "node ./install.js".into())];
        let got = diff(&inputs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "install.js");
        assert_eq!(got[0].reason, "script-file");
    }

    #[test]
    fn drifted_extra_code_file_lib_whitelisted() {
        let got = diff(&di(
            &[
                "package.json",
                "src/index.js",
                "lib/extra-payload.js", // lib/ is build output → suppressed
                "telemetry/sneaky.js",  // flagged
            ],
            &["package.json", "src/index.js"],
        ));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "telemetry/sneaky.js");
        assert_eq!(got[0].reason, "code-file");
    }

    #[test]
    fn package_json_files_whitelist_suppresses() {
        let mut inputs = di(&["package.json", "bundles/index.js"], &["package.json"]);
        inputs.package_json_files = vec!["bundles".into()];
        assert!(diff(&inputs).is_empty());
    }

    #[test]
    fn glob_whitelist_suppresses() {
        let mut inputs = di(&["package.json", "out/a.js"], &["package.json"]);
        inputs.package_json_files = vec!["out/*.js".into()];
        assert!(diff(&inputs).is_empty());
    }

    #[test]
    fn binary_artifact_in_tarball_only() {
        let got = diff(&di(
            &["package.json", "bin/runtime.node"],
            &["package.json"],
        ));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].reason, "binary-file");
    }

    #[test]
    fn repo_subdir_stripped_for_monorepo() {
        let mut inputs = di(&["src/index.js"], &["packages/core/src/index.js"]);
        inputs.repo_subdir = "packages/core".into();
        assert!(diff(&inputs).is_empty());
    }

    #[test]
    fn empty_inputs_return_empty() {
        assert!(diff(&DiffInputs::default()).is_empty());
    }

    #[test]
    fn wrapper_script_file_always_fires() {
        let mut inputs = di(&["a.js", "index.js"], &["index.js"]);
        inputs.hook_scripts = vec![("postinstall".into(), "node ./a.js".into())];
        let (cap, ev) = detect_tarball_drift(&inputs).unwrap();
        assert_eq!(cap, Capability::TarballDrift);
        assert!(has_script_file_evidence(&ev));
    }

    #[test]
    fn wrapper_small_drift_fires() {
        // 1 non-script drift file, well under the cutoff → fires.
        let got = detect_tarball_drift(&di(
            &["package.json", "src/index.js", "telemetry/x.js"],
            &["package.json", "src/index.js"],
        ));
        assert!(got.is_some());
    }

    #[test]
    fn wrapper_wholesale_mismatch_suppressed() {
        // Every tarball code file "drifts" (wrong subdir) → suppressed.
        let tarball: Vec<&str> = vec![
            "a.js", "b.js", "c.js", "d.js", "e.js", "f.js", "g.js", "h.js",
        ];
        let got = detect_tarball_drift(&di(&tarball, &["unrelated/z.js"]));
        assert!(got.is_none(), "wholesale mismatch should be suppressed");
    }

    #[test]
    fn check_over_package_no_repo_files_dormant() {
        let mut pkg = NormalizedPackage::default();
        pkg.files.insert("evil.js".into(), Vec::new());
        assert!(check_tarball_drift(&pkg, &[], "").is_empty());
    }
}
