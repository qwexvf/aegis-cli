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
use crate::pm::argv::{self, InstallKind};
use crate::pm::spec::{self, SpecKind};
use crate::pm::{exec, Pm};
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
        // Lockfile installs land in a later commit; pass through rather than
        // pretending to have checked them.
        InstallKind::Lockfile => return exec::exec_real(pm.name(), args),
        InstallKind::Named => {}
    }

    let ctx = PolicyCtx {
        fail_on: fail_on_threshold(),
        allow_unchecked: allow_unchecked(),
        uncertain_parse: walk.saw_unknown_flag,
    };

    let specs: Vec<spec::Spec> = walk
        .specs
        .iter()
        .map(|raw| spec::parse(pm.def().spec_style, raw))
        .collect();

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

    let outcomes = check_all(pm.ecosystem(), &registry, &ctx);
    report(&outcomes);
    record_audit(pm, &outcomes);

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

/// Resolve, scan and judge every spec.
fn check_all(eco: Ecosystem, specs: &[&spec::Spec], ctx: &PolicyCtx) -> Vec<Outcome> {
    let http = aegis_net::default_client();

    // Resolve first: everything downstream needs an exact version.
    let resolved: Vec<(usize, Result<String, ResolveError>)> = specs
        .iter()
        .enumerate()
        .map(|(i, s)| (i, resolve_version(&http, eco, &s.name, &s.requested)))
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
        let cap_v = match crate::pkgcache::get(eco_s, &s.name, &version) {
            Some(v) => v,
            None => match crate::scan::fetch_and_scan_package(eco, &s.name, &version) {
                Ok(sp) => {
                    let v = verdict(&sp.assessment, &RiskAssessment::default());
                    crate::pkgcache::put(eco_s, &s.name, &version, v);
                    v
                }
                Err(e) => {
                    let why = Unchecked::ScanFailed(e);
                    return Outcome {
                        name: s.name.clone(),
                        version,
                        action: evaluate_unchecked(&why, ctx),
                        verdict: None,
                        unchecked: Some(why),
                        advisories: advs,
                    };
                }
            },
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
                eprintln!("[aegis] BLOCK {who} ({})", v.name());
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
fn record_audit(pm: Pm, outcomes: &[Outcome]) {
    for o in outcomes {
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
