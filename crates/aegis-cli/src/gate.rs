//! The install gate: check what is about to be installed, before the package
//! manager fetches and runs it.
//!
//! This is the piece that makes `aegis` sit *in front of* a package manager
//! rather than scanning after the fact. By the time a lockfile exists to run
//! `aegis ci` on, a postinstall script has already executed.
//!
//! It composes existing machinery and grows no scoring of its own: the
//! capability/advisory combination is the same `cap_v.max(adv_v)` that
//! `run_ci` uses, so a package that fails `aegis ci` also fails the gate —
//! the property users will assume.
//!
//! One trap worth naming: the reachability downgrade that `run_ci` applies is
//! deliberately **not** used here. A package you are installing right now is
//! by definition not yet imported, so `downgrade_unused` would soften every
//! new package's verdict by one level — silently weakening the exact case the
//! gate exists to catch.

pub(crate) mod policy;

use std::process::ExitCode;

use aegis_domain::{
    verdict, verdict_for_advisories, Advisory, AdvisoryQuery, Dependency, Ecosystem,
    RiskAssessment, VerdictKind,
};
use aegis_registry::{resolve_version, ResolveError};
use rayon::prelude::*;

use crate::enrich::advisories_by_key;
use crate::npmrc::NpmConfig;
use crate::pm::argv::{self, InstallKind};
use crate::pm::spec::{self, SpecKind};
use crate::pm::{exec, Pm, SpecStyle};
use policy::{evaluate, evaluate_unchecked, Action, PolicyCtx, Unchecked};

/// Cap on parallel package scans. Unlike `ci` — a CI job that may use the
/// whole box — the gate runs in front of an interactive command, and each
/// task does a multi-megabyte blocking tarball fetch.
fn concurrency() -> usize {
    std::env::var("AEGIS_GATE_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(4)
        })
}

/// What the gate decided about one package.
struct Outcome {
    name: String,
    /// Resolved version, or the raw request when we never got that far.
    version: String,
    action: Action,
    verdict: Option<VerdictKind>,
    unchecked: Option<Unchecked>,
    advisories: Vec<Advisory>,
}

/// Entry point for `aegis <pm> <args...>`.
pub(crate) fn run(pm: Pm, args: &[String]) -> ExitCode {
    // A bypass, or a gate we are already inside: hand off untouched.
    if exec::gate_suppressed() {
        return exec::exec_real(pm.name(), args);
    }

    let walk = argv::walk(pm, args);
    match walk.kind {
        // Not an install at all — `npm run build`, `cargo check`.
        InstallKind::NotInstall => return exec::exec_real(pm.name(), args),
        InstallKind::Lockfile | InstallKind::Named => {}
    }

    let ctx = PolicyCtx {
        fail_on: fail_on_threshold(),
        allow_unchecked: allow_unchecked(),
        uncertain_parse: walk.saw_unknown_flag,
    };

    let specs: Vec<spec::Spec> = if walk.kind == InstallKind::Lockfile {
        match lockfile_specs(pm, &walk) {
            Ok(v) => v,
            Err(e) => {
                // Nothing to check is not the same as nothing wrong, but
                // refusing every `npm install` in a directory we cannot read a
                // lockfile from would be worse than useless.
                eprintln!("[aegis] lockfile not checked: {e}");
                return exec::exec_real(pm.name(), args);
            }
        }
    } else {
        walk.specs
            .iter()
            .map(|raw| spec::parse(pm.def().spec_style, raw))
            .collect()
    };

    // Non-registry specs (paths, git refs, workspace protocols) have nothing
    // to look up. Report them as skipped rather than silently ignoring them —
    // that is real missing coverage and the user should see it.
    for s in &specs {
        if let SpecKind::NonRegistry(why) = &s.kind {
            eprintln!("[aegis] skipped {} ({why}, nothing to verify)", s.raw);
        }
    }
    let registry: Vec<&spec::Spec> = specs
        .iter()
        .filter(|s| s.kind == SpecKind::Registry)
        .collect();
    if registry.is_empty() {
        return exec::exec_real(pm.name(), args);
    }

    let npm_cfg = NpmConfig::load(std::path::Path::new(walk.dir.as_deref().unwrap_or(".")));
    let outcomes = check_all(pm.ecosystem(), &registry, &ctx, walk.kind, &npm_cfg);
    report(&outcomes);
    record_audit(pm, &outcomes, walk.kind);

    if outcomes.iter().any(|o| o.action.blocks()) {
        // Env vars, not flags: everything after `aegis <pm>` is forwarded to
        // the manager verbatim, so an aegis flag there would collide with
        // whatever the manager adds next.
        let unchecked = outcomes.iter().any(|o| o.action == Action::BlockUnchecked);
        eprintln!("\n[aegis] install blocked. Bypass with AEGIS_NO_GATE=1.");
        if unchecked {
            eprintln!(
                "        To accept packages that could not be verified: \
                 AEGIS_GATE_ALLOW_UNCHECKED=1"
            );
        }
        return ExitCode::from(1);
    }
    // Everything the gate wants to say or record has to happen before this:
    // exec replaces the process and never returns.
    exec::exec_real(pm.name(), args)
}

/// Every dependency the lockfile pins, as already-exact specs.
///
/// This closes the biggest hole in the Go original: a bare `npm install` or
/// `npm ci` parses to zero named packages there, so the gate checked nothing
/// at all — even though that is where a poisoned transitive dependency
/// actually lands.
///
/// Versions from a lockfile are exact, so resolution costs no network call,
/// and the verdict cache makes a repeat install of an unchanged tree cheap.
fn lockfile_specs(pm: Pm, walk: &argv::Walk) -> Result<Vec<spec::Spec>, String> {
    let dir = walk.dir.clone().unwrap_or_default();
    let base = std::path::Path::new(if dir.is_empty() { "." } else { &dir });

    // pip names its requirement files on the command line; everyone else has
    // a fixed set to look for.
    let candidates: Vec<std::path::PathBuf> = if !walk.requirement_files.is_empty() {
        walk.requirement_files
            .iter()
            .map(|f| base.join(f))
            .collect()
    } else {
        // Walk up from the target directory. In a workspace the lockfile sits
        // at the root while the install runs in a package subdirectory
        // (`pnpm install -C packages/web`, `npm install --prefix`), and
        // looking only in that directory found nothing — so the install was
        // passed through unchecked, silently.
        let mut found = Vec::new();
        let mut dir = base.to_path_buf();
        loop {
            for f in pm.def().lockfiles {
                let p = dir.join(f);
                if p.is_file() {
                    found.push(p);
                }
            }
            if !found.is_empty() {
                break;
            }
            // Stop at a repository boundary: beyond it we would be reading
            // some unrelated project's lockfile.
            if dir.join(".git").exists() {
                break;
            }
            match dir.parent() {
                Some(parent) if parent != dir => dir = parent.to_path_buf(),
                _ => break,
            }
        }
        found
    };
    if candidates.is_empty() {
        return Err(format!(
            "no lockfile found in {} or its parents",
            base.display()
        ));
    }

    // A file named with `-r` is a requirements file by definition, whatever it
    // is called. Real projects use requirements-dev.txt, dev-requirements.txt,
    // requirements/base.txt — matching only the literal name `requirements.txt`
    // left every one of those silently unchecked.
    let named_by_flag = !walk.requirement_files.is_empty();

    let mut out = Vec::new();
    for path in candidates {
        let name = if named_by_flag {
            "requirements.txt".to_string()
        } else {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string()
        };
        // bun.lockb is binary and has no parser. Say so rather than reporting
        // a clean run over a file we never read.
        if name == "bun.lockb" {
            eprintln!("[aegis] skipped bun.lockb (binary lockfile, no parser)");
            continue;
        }
        let raw = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;

        // A requirements file is not a lockfile: most entries are ranges
        // (`pytest>=2.8.0,<10`) or bare names, and the lockfile parser keeps
        // only `==` pins. That silently checked 1 of 6 dependencies on a real
        // project. Parse the PEP 508 lines directly instead and let the
        // resolver turn each range into the version that would actually be
        // installed.
        if named_by_flag {
            out.extend(requirements_specs(&raw));
            continue;
        }

        let deps = aegis_lockfile::parse_file(&name, &raw, &aegis_lockfile::DirectMap::new())
            .map_err(|e| format!("{}: {e}", path.display()))?
            .ok_or_else(|| format!("{}: no parser", path.display()))?;
        for d in deps {
            // A lockfile pins local and VCS dependencies too — `file:`,
            // `link:`, `workspace:`, `git+…`. Those have no registry entry, so
            // looking them up fails, and under a fail-closed gate a failed
            // lookup blocks. Left unchecked this turns every workspace with a
            // local dependency into an install that cannot proceed.
            let style = pm.def().spec_style;
            let kind = match spec::non_registry_reason(style, &d.version)
                .or_else(|| spec::non_registry_reason(style, &d.name))
            {
                Some(why) => spec::SpecKind::NonRegistry(why),
                None => spec::SpecKind::Registry,
            };
            out.push(spec::Spec {
                raw: format!("{}@{}", d.name, d.version),
                name: d.name,
                requested: d.version,
                kind,
            });
        }
    }
    out.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.requested.cmp(&b.requested))
    });
    out.dedup_by(|a, b| a.name == b.name && a.requested == b.requested);
    Ok(out)
}

/// Parse a pip requirements file into specs, ranges included.
///
/// Handles comments, blank lines, line continuations and the `-r`/`-c`
/// include directives (reported as skipped rather than silently dropped —
/// following them would need recursion and its own cycle guard).
fn requirements_specs(raw: &[u8]) -> Vec<spec::Spec> {
    let text = String::from_utf8_lossy(raw);
    let mut joined = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l.strip_suffix('\\') {
            joined.push_str(rest.trim_end());
            joined.push(' ');
            continue;
        }
        joined.push_str(l);
        joined.push('\n');
    }

    let mut out = Vec::new();
    for entry in joined.lines() {
        let e = entry.split('#').next().unwrap_or(entry).trim();
        if e.is_empty() {
            continue;
        }
        // Options, not packages. `-e .` and `-r other.txt` included.
        if e.starts_with('-') {
            continue;
        }
        let parsed = spec::parse(SpecStyle::Pep508, e);
        if parsed.name.is_empty() {
            continue;
        }
        out.push(parsed);
    }
    out
}

/// Resolve, scan and judge every spec.
fn check_all(
    eco: Ecosystem,
    specs: &[&spec::Spec],
    ctx: &PolicyCtx,
    kind: InstallKind,
    npm_cfg: &NpmConfig,
) -> Vec<Outcome> {
    // A lockfile install means every pinned dependency, transitives included —
    // hundreds of packages. Capability-scanning all of them costs a tarball
    // fetch and an AST parse each: measured at over 90 seconds for a real
    // 922-dependency lockfile, in front of a command the user is waiting on.
    // Nobody keeps that installed.
    //
    // So lockfile mode checks advisories only by default. That is one batched
    // OSV query for the whole tree, already disk-cached, and it catches the
    // case that matters most here — a known-vulnerable version already pinned
    // in the tree. AEGIS_GATE_DEEP=1 opts into the full capability scan.
    //
    // Named installs always get the full scan: there are a handful of them,
    // the user typed them, and a brand-new package with no advisory history is
    // exactly where capability analysis earns its keep.
    let deep = kind == InstallKind::Named
        || std::env::var_os("AEGIS_GATE_DEEP").is_some_and(|v| !v.is_empty());
    let http = aegis_net::default_client();

    // Resolve first: everything downstream needs an exact version.
    let resolved: Vec<(usize, Result<String, ResolveError>)> = specs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let r = if eco == Ecosystem::Npm {
                let base = npm_cfg.registry_for(&s.name);
                let tok = npm_cfg.token_for(&base);
                if aegis_registry::is_exact_version(&s.requested) {
                    Ok(s.requested.clone())
                } else {
                    aegis_registry::resolve_npm_auth(
                        &http,
                        &base,
                        &s.name,
                        &s.requested,
                        tok.as_deref(),
                    )
                }
            } else {
                resolve_version(&http, eco, &s.name, &s.requested)
            };
            (i, r)
        })
        .collect();

    // One batched advisory call for the whole install rather than one per
    // package — `advisories_by_key` already has the 7-day OSV disk cache
    // underneath it.
    let queries: Vec<AdvisoryQuery> = resolved
        .iter()
        .filter_map(|(i, r)| r.as_ref().ok().map(|v| (i, v)))
        .map(|(i, v)| AdvisoryQuery {
            ecosystem: eco,
            name: specs[*i].name.clone(),
            version: v.clone(),
        })
        .collect();
    let adv_map = if queries.is_empty() {
        Ok(Default::default())
    } else {
        advisories_by_key(&queries)
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(concurrency())
        .build();

    let judge = |(i, res): &(usize, Result<String, ResolveError>)| -> Outcome {
        let s = specs[*i];
        let version = match res {
            Ok(v) => v.clone(),
            Err(e) => {
                let why = match e {
                    ResolveError::NotFound | ResolveError::NoMatchingVersion => Unchecked::NotFound,
                    ResolveError::Transport(m) => Unchecked::Unreachable(m.clone()),
                    ResolveError::Unsupported => {
                        Unchecked::ScanFailed("no resolver for this ecosystem".into())
                    }
                };
                return Outcome {
                    name: s.name.clone(),
                    version: s.requested.clone(),
                    action: evaluate_unchecked(&why, ctx),
                    verdict: None,
                    unchecked: Some(why),
                    advisories: Vec::new(),
                };
            }
        };

        // An advisory lookup that failed wholesale means we verified nothing.
        let advs = match &adv_map {
            Ok(m) => {
                let dep = Dependency {
                    ecosystem: eco,
                    name: s.name.clone(),
                    version: version.clone(),
                    ..Default::default()
                };
                m.get(&dep.versioned_key()).cloned().unwrap_or_default()
            }
            Err(e) => {
                let why = Unchecked::Unreachable(e.clone());
                return Outcome {
                    name: s.name.clone(),
                    version,
                    action: evaluate_unchecked(&why, ctx),
                    verdict: None,
                    unchecked: Some(why),
                    advisories: Vec::new(),
                };
            }
        };

        // The capability half is cacheable: a published version's code never
        // changes. The advisory half above is not, so it is never cached here.
        let eco_s = eco.as_str();
        let cap_v = if !deep {
            VerdictKind::Safe
        } else {
            match crate::pkgcache::get(eco_s, &s.name, &version) {
                Some(v) => v,
                None => {
                    let base = (eco == Ecosystem::Npm).then(|| npm_cfg.registry_for(&s.name));
                    let tok = base.as_deref().and_then(|b| npm_cfg.token_for(b));
                    let http2 = aegis_net::default_client();
                    match crate::scan::fetch_and_scan_package_at(
                        &http2,
                        eco,
                        &s.name,
                        &version,
                        base.as_deref(),
                        tok.as_deref(),
                    ) {
                        Ok(sp) => {
                            let v = verdict(&sp.assessment, &RiskAssessment::default());
                            crate::pkgcache::put(eco_s, &s.name, &version, v);
                            v
                        }
                        Err(e) => {
                            // A private registry cannot tell "absent" from "no
                            // access": both come back 404/401. Blocking there took
                            // every private-registry user offline, so an
                            // unreachable *private* host is a warning while the
                            // public registry still blocks — a 404 there is a real
                            // signal that the name is unclaimed and squattable.
                            let private = base.as_deref().is_some_and(|b| !NpmConfig::is_public(b));
                            let why = Unchecked::ScanFailed(e);
                            let action = if private {
                                Action::WarnUnchecked
                            } else {
                                evaluate_unchecked(&why, ctx)
                            };
                            return Outcome {
                                name: s.name.clone(),
                                version,
                                action,
                                verdict: None,
                                unchecked: Some(why),
                                advisories: advs,
                            };
                        }
                    }
                }
            }
        };

        // Same composition as `run_ci`, minus the reachability downgrade —
        // see the module docs for why that one must not be reused here.
        let adv_v = verdict_for_advisories(&advs);
        let final_v = cap_v.max(adv_v);

        Outcome {
            name: s.name.clone(),
            version,
            action: evaluate(final_v, ctx),
            verdict: Some(final_v),
            unchecked: None,
            advisories: advs,
        }
    };

    match pool {
        Ok(p) => p.install(|| resolved.par_iter().map(judge).collect()),
        // A thread pool we could not build is not a reason to skip the gate.
        Err(_) => resolved.iter().map(judge).collect(),
    }
}

/// Everything goes to stderr: stdout belongs to the package manager.
fn report(outcomes: &[Outcome]) {
    for o in outcomes {
        let who = format!("{}@{}", o.name, o.version);
        match (&o.action, &o.unchecked, o.verdict) {
            (Action::Proceed, _, Some(v)) => {
                if v > VerdictKind::Safe {
                    eprintln!("[aegis] {} {who}", v.name());
                }
            }
            (Action::Block, _, Some(v)) => {
                // `BLOCK pkg (safe)` reads as a contradiction. It happens when
                // the threshold is lowered below Block, so name the threshold
                // rather than leaving the verdict looking self-contradictory.
                if v < VerdictKind::Block {
                    eprintln!(
                        "[aegis] BLOCK {who} (verdict {}, at or above your \
                         AEGIS_GATE_FAIL_ON={} threshold)",
                        v.name(),
                        fail_on_threshold().name()
                    );
                } else {
                    eprintln!("[aegis] BLOCK {who} ({})", v.name());
                }
                for a in &o.advisories {
                    eprintln!("          {} [{}] {}", a.id, a.severity.as_str(), a.summary);
                }
            }
            (Action::BlockUnchecked, Some(why), _) => {
                eprintln!("[aegis] BLOCK {who} — {why}");
            }
            (Action::WarnUnchecked, Some(why), _) => {
                eprintln!("[aegis] unverified {who} — {why} (allowed)");
            }
            _ => {}
        }
    }
}

/// One audit row per decision, in the same shape `ci` and `aur` write, so the
/// log stays one stream. Written before exec, which never returns.
///
/// Lockfile mode records only the decisions that were not "safe". A bare
/// install judges the whole tree — 922 dependencies on a real project — and
/// writing a row for each buries the handful that matter under ~900 lines of
/// noise per install. The log answers "what did aegis decide", and for a
/// clean tree the answer is "nothing worth writing down". Named installs keep
/// every row: there are a few of them and the user asked for them by name.
fn record_audit(pm: Pm, outcomes: &[Outcome], kind: InstallKind) {
    let only_notable = kind == InstallKind::Lockfile;
    for o in outcomes {
        if only_notable && o.action == Action::Proceed && o.verdict == Some(VerdictKind::Safe) {
            continue;
        }
        let mut e = crate::audit::Entry::new("gate");
        e.ecosystem = pm.ecosystem().as_str().to_string();
        e.package = o.name.clone();
        e.version = o.version.clone();
        e.decision = match o.action {
            Action::Proceed => o
                .verdict
                .map(|v| v.name().to_string())
                .unwrap_or_else(|| "safe".into()),
            Action::Block => "block".into(),
            Action::BlockUnchecked => "block-unchecked".into(),
            Action::WarnUnchecked => "unchecked".into(),
        };
        crate::audit::write(&e);
    }
}

/// Verdict threshold for a *verified* package.
fn fail_on_threshold() -> VerdictKind {
    std::env::var("AEGIS_GATE_FAIL_ON")
        .ok()
        .and_then(|s| VerdictKind::parse(&s))
        .unwrap_or(VerdictKind::Block)
}

fn allow_unchecked() -> bool {
    std::env::var_os("AEGIS_GATE_ALLOW_UNCHECKED").is_some_and(|v| !v.is_empty())
}
