//! `aegis doctor` — check that the environment can actually run a scan.
//!
//! Ported from Go's `doctor_command.go`, with the checks retargeted at what
//! the Rust port depends on. Go checked its Cloud API and a fingerprint
//! cache; neither exists here. What matters instead is whether the advisory
//! feeds are reachable, whether the cache is writable, and whether the
//! allowlist parses — the three things whose silent failure changes a
//! verdict without anyone noticing.
//!
//! Exit code follows Go: any `fail` exits 1, warnings alone exit 0. A
//! warning means degraded but usable; a failure means results would be
//! wrong or absent.

use std::process::ExitCode;

use aegis_net::HttpClient;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn mark(self) -> &'static str {
        match self {
            Status::Pass => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

fn pass(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Pass,
        detail: detail.into(),
    }
}
fn warn(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Warn,
        detail: detail.into(),
    }
}
fn fail(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Fail,
        detail: detail.into(),
    }
}

#[derive(Serialize)]
struct Report {
    checks: Vec<Check>,
    ok: bool,
}

pub(crate) fn run_doctor(offline: bool, json: bool) -> ExitCode {
    let mut checks = vec![
        check_runtime(),
        check_cache_dir(),
        check_allowlist(),
        check_project_dir(),
        check_git(),
        check_github_token(),
    ];
    checks.push(if offline {
        warn("advisory-feeds", "skipped (--offline)")
    } else {
        check_feeds()
    });

    let failed = checks.iter().any(|c| c.status == Status::Fail);

    if json {
        let report = Report {
            checks,
            ok: !failed,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        for c in &checks {
            println!("[{}] {:<16} {}", c.status.mark(), c.name, c.detail);
        }
        let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
        println!();
        if failed {
            println!("doctor: FAILED — fix the failures above before trusting a scan");
        } else if warns > 0 {
            println!("doctor: usable, {warns} warning(s)");
        } else {
            println!("doctor: all checks passed");
        }
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn check_runtime() -> Check {
    pass(
        "runtime",
        format!(
            "aegis {} on {}/{}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    )
}

/// The cache is not optional in practice: without it every run refetches
/// the ~1.5 MB KEV feed, and an unwritable cache dir fails silently at the
/// point of use rather than here.
fn check_cache_dir() -> Check {
    let dir = crate::cache::cache_base();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return fail("cache-dir", format!("{}: {e}", dir.display()));
    }
    let probe = dir.join(".doctor-write-probe");
    match std::fs::write(&probe, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            pass("cache-dir", format!("{} writable", dir.display()))
        }
        Err(e) => fail("cache-dir", format!("{} not writable: {e}", dir.display())),
    }
}

/// A malformed user allowlist is the dangerous case: it silently suppresses
/// nothing (or everything) and the scan still reports success.
fn check_allowlist() -> Check {
    let n = aegis_domain::builtin_allow_rules().len();

    for candidate in ["aegis.toml", ".aegis.toml"] {
        let p = std::path::Path::new(candidate);
        if !p.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(p) else {
            return warn("allowlist", format!("{candidate}: unreadable"));
        };
        return match toml::from_str::<toml::Value>(&raw) {
            Ok(_) => pass("allowlist", format!("{n} builtin rules + {candidate}")),
            Err(e) => fail("allowlist", format!("{candidate} does not parse: {e}")),
        };
    }
    pass(
        "allowlist",
        format!("{n} builtin rules (no project allowlist)"),
    )
}

/// Not a failure — plenty of commands take an explicit path — but knowing
/// there is nothing scannable here explains an empty result.
fn check_project_dir() -> Check {
    const LOCKFILES: &[&str] = &[
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "Cargo.lock",
        "go.sum",
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Gemfile.lock",
        "composer.lock",
        "pom.xml",
        "gradle.lockfile",
        "mix.lock",
        "pubspec.lock",
        "Podfile.lock",
        "Package.resolved",
        "packages.lock.json",
        "renv.lock",
        "cpanfile.snapshot",
        "cabal.project.freeze",
        "stack.yaml.lock",
        "manifest.toml",
        "nimble.lock",
        "elm.json",
    ];
    let found: Vec<&str> = LOCKFILES
        .iter()
        .copied()
        .filter(|f| std::path::Path::new(f).is_file())
        .collect();
    if found.is_empty() {
        warn("project-dir", "no lockfile in the current directory")
    } else {
        pass("project-dir", found.join(", "))
    }
}

/// `hook` and the AUR history rules shell out to git.
fn check_git() -> Check {
    match std::process::Command::new("git").arg("--version").output() {
        Ok(o) if o.status.success() => {
            pass("git", String::from_utf8_lossy(&o.stdout).trim().to_string())
        }
        _ => warn("git", "not found — `hook` and AUR history checks need it"),
    }
}

/// Without a token, GHSA lookups are unauthenticated and rate-limited hard.
/// Not a failure: OSV alone still produces advisories.
fn check_github_token() -> Check {
    match std::env::var("GITHUB_TOKEN") {
        Ok(v) if !v.trim().is_empty() => pass("github-token", "set (GHSA lookups authenticated)"),
        _ => warn(
            "github-token",
            "unset — GHSA lookups are rate-limited; OSV still works",
        ),
    }
}

/// Reachability of the feeds a scan actually queries. A timeout here is a
/// warning, not a failure: `ci --offline` is a supported mode.
fn check_feeds() -> Check {
    const FEEDS: &[(&str, &str)] = &[
        ("OSV", "https://api.osv.dev/v1/query"),
        ("EPSS", "https://api.first.org/data/v1/epss?limit=1"),
        (
            "KEV",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
    ];
    let client = aegis_net::default_client();
    let mut down = Vec::new();
    for (name, url) in FEEDS {
        // HEAD-equivalent: any response at all proves reachability. A
        // 4xx from a GET-only endpoint still means the host answered.
        match client.get(url, &[]) {
            Ok(_) => {}
            Err(_) => down.push(*name),
        }
    }
    if down.is_empty() {
        pass("advisory-feeds", "OSV, EPSS, KEV reachable")
    } else {
        warn(
            "advisory-feeds",
            format!("unreachable: {} — use --offline", down.join(", ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_always_passes() {
        let c = check_runtime();
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn allowlist_reports_the_builtin_rule_count() {
        let c = check_allowlist();
        assert_ne!(c.status, Status::Fail);
        assert!(c.detail.contains("builtin"));
    }

    #[test]
    fn cache_dir_check_creates_and_probes() {
        let c = check_cache_dir();
        assert_ne!(c.status, Status::Fail, "{}", c.detail);
        // The probe file must not be left behind.
        assert!(!crate::cache::cache_base()
            .join(".doctor-write-probe")
            .exists());
    }

    #[test]
    fn status_marks_are_fixed_width() {
        assert_eq!(Status::Pass.mark().len(), Status::Fail.mark().len());
        assert_eq!(Status::Warn.mark().len(), Status::Fail.mark().len());
    }
}
