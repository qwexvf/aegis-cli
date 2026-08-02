//! `aegis allowlist` — manage capability suppressions.
//!
//! Ported from Go's `allowlist_command.go`. The Rust port previously only
//! dumped the builtin rules read-only; this adds the mutating half.
//!
//! Two writable scopes, mirroring Go:
//!
//! - **user** — `$XDG_CONFIG_HOME/aegis/allowlist.toml`, applies everywhere.
//! - **project** — `aegis.toml` in the current directory, committed with
//!   the repo so a team shares the same suppressions.
//!
//! Both use the same `[[allow]]` shape the scanner already reads, so a rule
//! added here is picked up by `analyze` and `run` with no extra wiring.
//!
//! `--reason` is required on `add`. A suppression with no recorded reason
//! is indistinguishable from a mistake six months later, and the whole
//! point of an allowlist is that someone decided the risk was acceptable.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aegis_domain::{AllowRule, AllowSet, Capability, Ecosystem, ALL_CAPABILITIES};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    User,
    Project,
}

impl Scope {
    pub(crate) fn parse(s: &str) -> Result<Scope, String> {
        match s {
            "user" => Ok(Scope::User),
            "project" => Ok(Scope::Project),
            other => Err(format!("invalid scope {other:?} (use user or project)")),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
    fn path(self) -> PathBuf {
        match self {
            Scope::User => user_config_dir().join("allowlist.toml"),
            Scope::Project => PathBuf::from("aegis.toml"),
        }
    }
}

fn user_config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(std::env::temp_dir)
        .join("aegis")
}

/// The on-disk `[[allow]]` entry. Field names match what the scanner
/// already parses, so both scopes stay readable by `analyze --allowlist`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct RuleEntry {
    #[serde(default = "default_eco")]
    pub ecosystem: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version_range: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

fn default_eco() -> String {
    "npm".into()
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AllowFile {
    #[serde(default, rename = "allow", skip_serializing_if = "Vec::is_empty")]
    allow: Vec<RuleEntry>,
    /// Anything else in `aegis.toml` (tasks, parallelism, …) is preserved
    /// verbatim so editing the allowlist never eats the rest of the config.
    #[serde(flatten)]
    rest: toml::Table,
}

fn load(path: &Path) -> Result<AllowFile, String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AllowFile::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn save(path: &Path, f: &AllowFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
    }
    let body = toml::to_string_pretty(f).map_err(|e| format!("encode: {e}"))?;
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn capability_by_name(slug: &str) -> Option<Capability> {
    ALL_CAPABILITIES.iter().copied().find(|c| c.name() == slug)
}

fn entry_to_rule(e: &RuleEntry, source: &str) -> Result<AllowRule, String> {
    let eco = crate::util::parse_ecosystem(&e.ecosystem)
        .ok_or_else(|| format!("unknown ecosystem {:?}", e.ecosystem))?;
    let capability = match e.capability.as_deref() {
        None | Some("") | Some("*") => None,
        Some(slug) => {
            Some(capability_by_name(slug).ok_or_else(|| format!("unknown capability {slug:?}"))?)
        }
    };
    Ok(AllowRule {
        ecosystem: eco,
        name: e.name.clone(),
        version_range: e.version_range.clone(),
        capability,
        reason: e.reason.clone(),
        source: source.to_string(),
    })
}

// --- add ---

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_add(
    name: &str,
    ecosystem: &str,
    capability: Option<&str>,
    version: &str,
    reason: &str,
    scope: &str,
) -> ExitCode {
    if reason.trim().is_empty() {
        eprintln!(
            "aegis: --reason is required (audit trail); e.g. --reason 'legitimate build tool'"
        );
        return ExitCode::from(2);
    }
    let scope = match Scope::parse(scope) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let entry = RuleEntry {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version_range: version.to_string(),
        capability: capability
            .filter(|c| !c.is_empty() && *c != "*")
            .map(String::from),
        reason: reason.to_string(),
    };
    // Validate before writing — a rule that cannot compile would silently
    // break every later scan that loads this file.
    if let Err(e) = entry_to_rule(&entry, scope.name()).and_then(|r| {
        AllowSet::new(vec![r])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }) {
        eprintln!("aegis: {e}");
        return ExitCode::from(2);
    }

    let path = scope.path();
    let mut f = match load(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    // Same (ecosystem, name, capability) replaces rather than duplicates.
    let replaced = f
        .allow
        .iter()
        .position(|r| {
            r.ecosystem == entry.ecosystem
                && r.name == entry.name
                && r.capability == entry.capability
        })
        .map(|i| {
            f.allow[i] = entry.clone();
            true
        })
        .unwrap_or_else(|| {
            f.allow.push(entry.clone());
            false
        });

    if let Err(e) = save(&path, &f) {
        eprintln!("aegis: {e}");
        return ExitCode::from(2);
    }
    let verb = if replaced { "replaced" } else { "added" };
    println!(
        "{verb} {} rule: {}/{}{} → {}",
        scope.name(),
        entry.ecosystem,
        entry.name,
        entry
            .capability
            .as_deref()
            .map(|c| format!(" [{c}]"))
            .unwrap_or_default(),
        path.display()
    );
    ExitCode::SUCCESS
}

// --- remove ---

pub(crate) fn run_remove(
    name: &str,
    ecosystem: &str,
    capability: Option<&str>,
    scope: &str,
) -> ExitCode {
    let scope = match Scope::parse(scope) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let path = scope.path();
    let mut f = match load(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let before = f.allow.len();
    f.allow.retain(|r| {
        let same = r.name == name && r.ecosystem == ecosystem;
        // No --capability removes every rule for the package; with one, only
        // the matching rule goes.
        match capability {
            None => !same,
            Some(c) => !(same && r.capability.as_deref() == Some(c)),
        }
    });
    let removed = before - f.allow.len();
    if removed == 0 {
        println!("no matching {} rule for {ecosystem}/{name}", scope.name());
        return ExitCode::SUCCESS;
    }
    if let Err(e) = save(&path, &f) {
        eprintln!("aegis: {e}");
        return ExitCode::from(2);
    }
    println!(
        "removed {removed} {} rule(s) → {}",
        scope.name(),
        path.display()
    );
    ExitCode::SUCCESS
}

// --- list ---

/// Every layer, in the order the scanner applies them.
fn all_layers() -> (Vec<AllowRule>, Vec<String>) {
    let mut rules = aegis_domain::builtin_allow_rules();
    let mut problems = Vec::new();
    for scope in [Scope::User, Scope::Project] {
        match load(&scope.path()) {
            Ok(f) => {
                for e in &f.allow {
                    match entry_to_rule(e, scope.name()) {
                        Ok(r) => rules.push(r),
                        Err(msg) => problems.push(format!("{}: {msg}", scope.path().display())),
                    }
                }
            }
            Err(msg) => problems.push(msg),
        }
    }
    (rules, problems)
}

pub(crate) fn run_list(json: bool) -> ExitCode {
    let (rules, problems) = all_layers();
    for p in &problems {
        eprintln!("aegis: warning: {p}");
    }
    if json {
        let view: Vec<_> = rules
            .iter()
            .map(|r| RuleView {
                source: &r.source,
                ecosystem: r.ecosystem.as_str(),
                name: &r.name,
                version_range: &r.version_range,
                capability: r.capability.map(|c| c.name()),
                reason: &r.reason,
            })
            .collect();
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<8} {:<9} {:<28} {:<10} {:<22} REASON",
        "SOURCE", "ECO", "NAME", "VERSION", "CAPABILITY"
    );
    for r in &rules {
        println!(
            "{:<8} {:<9} {:<28} {:<10} {:<22} {}",
            r.source,
            r.ecosystem.as_str(),
            trunc(&r.name, 28),
            if r.version_range.is_empty() {
                "*"
            } else {
                &r.version_range
            },
            r.capability.map(|c| c.name()).unwrap_or("*"),
            r.reason
        );
    }
    println!("{} rules", rules.len());
    ExitCode::SUCCESS
}

#[derive(Serialize)]
struct RuleView<'a> {
    source: &'a str,
    ecosystem: &'a str,
    name: &'a str,
    version_range: &'a str,
    capability: Option<&'a str>,
    reason: &'a str,
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

// --- test ---

/// `<ecosystem>/<name>@<version>` — Go's spec shape.
fn parse_spec(spec: &str) -> Result<(Ecosystem, String, String), String> {
    let (eco_s, rest) = spec
        .split_once('/')
        .ok_or_else(|| format!("expected <ecosystem>/<name>@<version>, got {spec:?}"))?;
    let eco = crate::util::parse_ecosystem(eco_s)
        .ok_or_else(|| format!("unknown ecosystem {eco_s:?}"))?;
    // Scoped npm names contain '@', so split on the LAST one.
    let (name, version) = match rest.rfind('@') {
        Some(i) if i > 0 => (&rest[..i], &rest[i + 1..]),
        _ => (rest, ""),
    };
    Ok((eco, name.to_string(), version.to_string()))
}

pub(crate) fn run_test(spec: &str) -> ExitCode {
    let (eco, name, version) = match parse_spec(spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("aegis: {e}");
            return ExitCode::from(2);
        }
    };
    let (rules, _) = all_layers();
    let set = match AllowSet::new(rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aegis: allowlist does not compile: {e}");
            return ExitCode::from(2);
        }
    };
    let matches = set.match_all(eco, &name, &version);
    if matches.is_empty() {
        println!("no rule suppresses {}/{name}@{version}", eco.as_str());
        return ExitCode::SUCCESS;
    }
    println!(
        "{} rule(s) match {}/{name}@{version}:",
        matches.len(),
        eco.as_str()
    );
    for m in &matches {
        println!(
            "  [{}] {} — {}",
            m.rule.source,
            m.rule
                .capability
                .map(|c| c.name())
                .unwrap_or("* (any capability)"),
            if m.rule.reason.is_empty() {
                "(no reason recorded)"
            } else {
                &m.rule.reason
            }
        );
    }
    ExitCode::SUCCESS
}

// --- verify ---

pub(crate) fn run_verify() -> ExitCode {
    let mut bad = 0usize;
    for scope in [Scope::User, Scope::Project] {
        let path = scope.path();
        if !path.is_file() {
            println!("[ok  ] {:<8} {} (absent)", scope.name(), path.display());
            continue;
        }
        match load(&path) {
            Err(msg) => {
                println!("[FAIL] {:<8} {msg}", scope.name());
                bad += 1;
            }
            Ok(f) => {
                let mut errs = Vec::new();
                let mut rules = Vec::new();
                for e in &f.allow {
                    match entry_to_rule(e, scope.name()) {
                        Ok(r) => rules.push(r),
                        Err(m) => errs.push(m),
                    }
                }
                if errs.is_empty() {
                    if let Err(e) = AllowSet::new(rules) {
                        errs.push(e.to_string());
                    }
                }
                if errs.is_empty() {
                    println!(
                        "[ok  ] {:<8} {} ({} rules)",
                        scope.name(),
                        path.display(),
                        f.allow.len()
                    );
                } else {
                    for e in &errs {
                        println!("[FAIL] {:<8} {}: {e}", scope.name(), path.display());
                    }
                    bad += errs.len();
                }
            }
        }
    }
    if bad > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parsing_rejects_junk() {
        assert!(Scope::parse("user").is_ok());
        assert!(Scope::parse("project").is_ok());
        assert!(Scope::parse("global").is_err());
    }

    #[test]
    fn spec_splits_on_the_last_at_for_scoped_names() {
        let (eco, name, ver) = parse_spec("npm/@scope/pkg@1.2.3").unwrap();
        assert_eq!(eco, Ecosystem::Npm);
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, "1.2.3");
    }

    #[test]
    fn spec_allows_a_missing_version() {
        let (_, name, ver) = parse_spec("npm/lodash").unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(ver, "");
    }

    #[test]
    fn spec_rejects_a_missing_ecosystem() {
        assert!(parse_spec("lodash@1.0.0").is_err());
    }

    #[test]
    fn entry_roundtrips_through_toml_with_the_scanner_shape() {
        let e = RuleEntry {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version_range: "^4".into(),
            capability: Some("dynamic-eval".into()),
            reason: "known safe".into(),
        };
        let f = AllowFile {
            allow: vec![e.clone()],
            rest: toml::Table::new(),
        };
        let text = toml::to_string_pretty(&f).unwrap();
        assert!(text.contains("[[allow]]"), "{text}");
        let back: AllowFile = toml::from_str(&text).unwrap();
        assert_eq!(back.allow[0], e);
    }

    #[test]
    fn unknown_capability_is_rejected_before_writing() {
        let e = RuleEntry {
            ecosystem: "npm".into(),
            name: "x".into(),
            version_range: String::new(),
            capability: Some("no-such-capability".into()),
            reason: "r".into(),
        };
        assert!(entry_to_rule(&e, "user").is_err());
    }

    #[test]
    fn wildcard_capability_means_any() {
        for c in [None, Some(""), Some("*")] {
            let e = RuleEntry {
                ecosystem: "npm".into(),
                name: "x".into(),
                version_range: String::new(),
                capability: c.map(String::from),
                reason: "r".into(),
            };
            assert!(entry_to_rule(&e, "user").unwrap().capability.is_none());
        }
    }

    #[test]
    fn other_config_keys_survive_a_rewrite() {
        // The failure this guards: editing the allowlist in aegis.toml must
        // not delete the user's [[task]] entries.
        let src = r#"
parallelism = 4

[[allow]]
name = "lodash"

[[task]]
name = "vendored"
path = "./vendor"
"#;
        let f: AllowFile = toml::from_str(src).unwrap();
        assert_eq!(f.allow.len(), 1);
        let out = toml::to_string_pretty(&f).unwrap();
        assert!(out.contains("parallelism"), "{out}");
        assert!(out.contains("[[task]]"), "{out}");
    }
}
