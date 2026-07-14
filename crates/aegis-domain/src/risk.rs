//! Weighted-sum risk scoring. Port of `internal/domain/risk.go`.
//!
//! Deliberately simple and explainable: every flag has a name and a
//! number. Pure — no I/O, no time, no env. Two scores feed the final
//! [`verdict`]: [`risk_score`] ("how dangerous on its own?") and
//! [`drift_score`] ("how much did the danger profile change?").

use crate::capability::{Capability, CapabilitySet};
use crate::types::{Dependency, Ecosystem, Fingerprint, InstallHook};

// --- per-capability weights ------------------------------------------
// Kept public so risk reports / docs / future config can reference them.

pub const WEIGHT_INSTALL_HOOK: i32 = 30;
pub const WEIGHT_SHELL_SPAWN: i32 = 20;
pub const WEIGHT_DYNAMIC_EVAL: i32 = 25;
pub const WEIGHT_BASE64_DECODE: i32 = 20;
pub const WEIGHT_NET_EGRESS: i32 = 10;
pub const WEIGHT_ENV_CRED_READ: i32 = 25;
pub const WEIGHT_FS_WRITE: i32 = 15;
pub const WEIGHT_RAW_IP_LITERAL: i32 = 15;
pub const WEIGHT_SIZE_ANOMALY: i32 = 5;
pub const WEIGHT_HOOK_CONTENT: i32 = 30;
pub const WEIGHT_CAPABILITY_ADD: i32 = 15;
pub const WEIGHT_MAINTAINER_SWAP: i32 = 30;

pub const WEIGHT_INSTALL_HOOK_SUSPICIOUS: i32 = 70;
pub const WEIGHT_OBFUSCATED_PAYLOAD: i32 = 60;
pub const WEIGHT_SUSPICIOUS_URL: i32 = 50;
pub const WEIGHT_BINARY_DROPPER: i32 = 35;
pub const WEIGHT_TYPOSQUAT_RISK: i32 = 40;
pub const WEIGHT_MAINTAINER_HIJACK_RISK: i32 = 50;
pub const WEIGHT_PATCH_VERSION_DRIFT: i32 = 35;
pub const WEIGHT_MAINTAINER_CHANGED: i32 = 55;
pub const WEIGHT_TARBALL_DRIFT: i32 = 60;
pub const WEIGHT_GIT_DEP_IN_OPTIONAL_DEP: i32 = 65;
pub const WEIGHT_UNLISTED_LARGE_FILE: i32 = 55;
pub const WEIGHT_VERSION_UNPUBLISHED: i32 = 75;
pub const WEIGHT_KNOWN_MALWARE_IOC: i32 = 100;
pub const WEIGHT_VCS_DEPENDENCY: i32 = 45;
pub const WEIGHT_PROVENANCE_MISSING: i32 = 10;
pub const WEIGHT_HARDCODED_SECRET: i32 = 80;
pub const WEIGHT_DEPRECATED: i32 = 15;

/// Env-var name prefixes that lift `EnvRead` from boring to
/// credential-theft-shaped. Matched case-insensitively. Mirrors
/// `credentialEnvVarRoots`.
const CREDENTIAL_ENV_VAR_ROOTS: &[&str] = &[
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GCP_",
    "NPM_TOKEN",
    "NPM_AUTH",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "DOCKER_AUTH",
    "DOCKERHUB_",
    "DATABASE_URL",
    "DB_PASS",
    "POSTGRES_",
    "MYSQL_",
    "PRIVATE_KEY",
    "SSH_",
    "STRIPE_",
    "TWILIO_",
    "SENDGRID_",
    "CIRCLE_TOKEN",
    "GITLAB_TOKEN",
];

/// One explainable contribution to a score. Mirrors `RiskFlag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskFlag {
    /// stable identifier ("shell-spawn", "install-hook", …).
    pub code: String,
    /// human-readable explanation.
    pub detail: String,
    /// numeric contribution (0 if suppressed).
    pub weight: i32,
    /// true when an allowlist rule excused this flag (still rendered).
    pub suppressed: bool,
    /// the matching rule's reason; empty when not suppressed.
    pub suppress_by: String,
}

impl RiskFlag {
    fn new(code: impl Into<String>, detail: impl Into<String>, weight: i32) -> Self {
        RiskFlag {
            code: code.into(),
            detail: detail.into(),
            weight,
            suppressed: false,
            suppress_by: String::new(),
        }
    }
}

/// A score plus the flags that produced it. Mirrors `RiskAssessment`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RiskAssessment {
    pub score: i32,
    pub flags: Vec<RiskFlag>,
}

impl RiskAssessment {
    fn add(&mut self, code: impl Into<String>, detail: impl Into<String>, weight: i32) {
        self.score += weight;
        self.flags.push(RiskFlag::new(code, detail, weight));
    }
}

/// Evaluate a fingerprint in isolation. Empty / unanalyzed fingerprints
/// return zero — but heuristic-only ecosystems that carry capabilities
/// or hooks without `analyzed` still score. Mirrors `RiskScore`.
pub fn risk_score(fp: Option<&Fingerprint>) -> RiskAssessment {
    let fp = match fp {
        Some(fp) => fp,
        None => return RiskAssessment::default(),
    };
    if !fp.analyzed && fp.capabilities.is_empty() && fp.hooks.is_empty() {
        return RiskAssessment::default();
    }

    let mut ra = RiskAssessment::default();

    // Install hooks first — highest-leverage supply-chain signal.
    for h in &fp.hooks {
        ra.add(
            "install-hook",
            format!("declares {} hook ({})", h.phase.name(), h.source),
            WEIGHT_INSTALL_HOOK,
        );
    }

    for c in &fp.capabilities {
        match c {
            Capability::ShellSpawn => {
                ra.add(c.name(), "spawns subprocess (shell/exec/spawn)", WEIGHT_SHELL_SPAWN)
            }
            Capability::DynamicEval => ra.add(
                c.name(),
                "constructs and runs code dynamically (eval/Function)",
                WEIGHT_DYNAMIC_EVAL,
            ),
            Capability::Base64Decode => {
                ra.add(c.name(), "decodes base64 at runtime", WEIGHT_BASE64_DECODE)
            }
            Capability::NetEgress => {
                ra.add(c.name(), "opens outbound network connection", WEIGHT_NET_EGRESS)
            }
            Capability::FsWriteOutsideRoot => ra.add(
                c.name(),
                "writes to filesystem outside its install root",
                WEIGHT_FS_WRITE,
            ),
            Capability::RawIpLiteral => {
                ra.add(c.name(), "embeds raw IP address in a URL", WEIGHT_RAW_IP_LITERAL)
            }
            Capability::EnvRead => {
                // Only flag when env names look credential-shaped.
                let names = credential_like_env_reads(&fp.env_reads);
                if !names.is_empty() {
                    ra.add(
                        "env-cred-read",
                        format!("reads credential-shaped env vars: {}", join_names(&names, 5)),
                        WEIGHT_ENV_CRED_READ,
                    );
                }
            }
            // Accounted for via hooks above; skip to avoid double-counting.
            Capability::InstallHookExec => {}
            Capability::InstallHookSuspicious => ra.add(
                c.name(),
                "install hook downloads-and-executes (curl|sh / wget|bash / node -e / base64|sh)",
                WEIGHT_INSTALL_HOOK_SUSPICIOUS,
            ),
            Capability::ObfuscatedPayload => ra.add(
                c.name(),
                "decodes-then-executes (eval(atob(...)) / Function(decode(...)))",
                WEIGHT_OBFUSCATED_PAYLOAD,
            ),
            Capability::SuspiciousUrl => ra.add(
                c.name(),
                "string literal points at a paste / chat-relay / tunnel host",
                WEIGHT_SUSPICIOUS_URL,
            ),
            Capability::BinaryDropper => ra.add(
                c.name(),
                "package ships an executable file (.exe/.dll/.so/.scpt) — unusual for a JS dep",
                WEIGHT_BINARY_DROPPER,
            ),
            Capability::TyposquatRisk => ra.add(
                c.name(),
                "name is within edit distance 2 of a top-1000 package",
                WEIGHT_TYPOSQUAT_RISK,
            ),
            Capability::MaintainerHijackRisk => ra.add(
                c.name(),
                "fresh publish + long gap from previous version + low downloads (maintainer-handover hijack pattern)",
                WEIGHT_MAINTAINER_HIJACK_RISK,
            ),
            Capability::PatchVersionDrift => ra.add(
                c.name(),
                "patch-version bump gained new capabilities (semver violation)",
                WEIGHT_PATCH_VERSION_DRIFT,
            ),
            Capability::TarballDrift => ra.add(
                c.name(),
                "published tarball contains source files not present in the upstream git tag",
                WEIGHT_TARBALL_DRIFT,
            ),
            Capability::MaintainerChanged => ra.add(
                c.name(),
                "publisher of this version differs from publisher of previous version (maintainer-handover compromise shape)",
                WEIGHT_MAINTAINER_CHANGED,
            ),
            Capability::GitDepInOptionalDep => ra.add(
                c.name(),
                "optionalDependency resolves to a git SHA commit — worm-propagation injection vector",
                WEIGHT_GIT_DEP_IN_OPTIONAL_DEP,
            ),
            Capability::UnlistedLargeFile => ra.add(
                c.name(),
                "tarball contains a ≥512 KB code file not in package.json files field — smuggled payload shape",
                WEIGHT_UNLISTED_LARGE_FILE,
            ),
            Capability::VersionUnpublished => ra.add(
                c.name(),
                "version was published then yanked — lockfile pins a package from an active incident window",
                WEIGHT_VERSION_UNPUBLISHED,
            ),
            Capability::KnownMalwareIoc => ra.add(
                c.name(),
                "tarball contains a confirmed-malware filename IOC (router_init.js / router_runtime.js / tanstack_runner.js)",
                WEIGHT_KNOWN_MALWARE_IOC,
            ),
            Capability::VcsDependency => ra.add(
                c.name(),
                "manifest pins a dep to a git/VCS URL — bypasses registry immutability; invisible to security scans",
                WEIGHT_VCS_DEPENDENCY,
            ),
            Capability::HardcodedSecret => ra.add(
                c.name(),
                "source contains a hardcoded credential (AWS key, GitHub token, PEM private key, Stripe/SendGrid/Twilio key)",
                WEIGHT_HARDCODED_SECRET,
            ),
        }
    }

    ra
}

/// Evaluate how much `next`'s behavioral profile differs from `prev`.
/// Both must be analyzed; otherwise zero. Mirrors `DriftScore`.
pub fn drift_score(prev: Option<&Fingerprint>, next: Option<&Fingerprint>) -> RiskAssessment {
    let (prev, next) = match (prev, next) {
        (Some(p), Some(n)) if p.analyzed && n.analyzed => (p, n),
        _ => return RiskAssessment::default(),
    };

    let mut ra = RiskAssessment::default();

    // 1. Install hooks: additions and content changes.
    hook_diff(&prev.hooks, &next.hooks, &mut ra);

    // 2. New capabilities gained in next.
    for c in next.capabilities.difference(&prev.capabilities).iter() {
        if *c == Capability::InstallHookExec {
            continue; // counted by hook_diff
        }
        ra.add(
            "capability-added",
            capability_added_detail(*c),
            WEIGHT_CAPABILITY_ADD,
        );
    }

    // 3. Source size delta (either direction).
    if let Some(d) = size_delta_signal(prev.source_size_bytes, next.source_size_bytes) {
        ra.add("size-anomaly", d, WEIGHT_SIZE_ANOMALY);
    }

    ra
}

fn hook_diff(prev: &[InstallHook], next: &[InstallHook], ra: &mut RiskAssessment) {
    for h in next {
        match prev.iter().find(|p| p.phase == h.phase) {
            None => ra.add(
                "install-hook-added",
                format!("new {} hook (none in prior version)", h.phase.name()),
                WEIGHT_INSTALL_HOOK,
            ),
            Some(old)
                if !old.sha256.is_empty() && !h.sha256.is_empty() && old.sha256 != h.sha256 =>
            {
                ra.add(
                    "install-hook-changed",
                    format!("{} hook content changed", h.phase.name()),
                    WEIGHT_HOOK_CONTENT,
                )
            }
            Some(_) => {}
        }
    }
}

/// Non-empty when source size changed by more than 100% either way.
/// Mirrors `sizeDeltaSignal`.
fn size_delta_signal(prev: i64, next: i64) -> Option<String> {
    if prev == 0 || next == 0 {
        return None;
    }
    if next >= 2 * prev {
        return Some("source size doubled or more vs prior version".to_string());
    }
    if next * 2 <= prev {
        return Some("source size dropped by more than half vs prior version".to_string());
    }
    None
}

fn credential_like_env_reads(env_reads: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for name in env_reads {
        let upper = name.to_ascii_uppercase();
        if CREDENTIAL_ENV_VAR_ROOTS
            .iter()
            .any(|root| upper.starts_with(root))
        {
            out.push(name.clone());
        }
    }
    out
}

/// Literal prefix on "capability-added" drift-flag details. Producer
/// here and the allowlist parser must stay in sync.
const CAPABILITY_ADDED_DETAIL_PREFIX: &str = "new capability since prior version: ";

fn capability_added_detail(c: Capability) -> String {
    format!("{}{}", CAPABILITY_ADDED_DETAIL_PREFIX, c.name())
}

fn join_names(names: &[String], max: usize) -> String {
    let slice = if names.len() > max {
        &names[..max]
    } else {
        names
    };
    slice.join(", ")
}

// --- Verdict ----------------------------------------------------------

/// A combined score bucketed into a UX category. Mirrors `VerdictKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    Safe,
    Review,
    Prompt,
    Block,
}

impl VerdictKind {
    pub fn name(self) -> &'static str {
        match self {
            VerdictKind::Safe => "safe",
            VerdictKind::Review => "review",
            VerdictKind::Prompt => "prompt",
            VerdictKind::Block => "block",
        }
    }
}

pub const VERDICT_THRESHOLD_REVIEW: i32 = 21;
pub const VERDICT_THRESHOLD_PROMPT: i32 = 61;
pub const VERDICT_THRESHOLD_BLOCK: i32 = 100;

/// Combine per-version risk and drift into a final bucket.
/// Combined = max(risk, drift). Mirrors `Verdict`.
pub fn verdict(risk: &RiskAssessment, drift: &RiskAssessment) -> VerdictKind {
    let combined = drift.score.max(risk.score);
    if combined >= VERDICT_THRESHOLD_BLOCK {
        VerdictKind::Block
    } else if combined >= VERDICT_THRESHOLD_PROMPT {
        VerdictKind::Prompt
    } else if combined >= VERDICT_THRESHOLD_REVIEW {
        VerdictKind::Review
    } else {
        VerdictKind::Safe
    }
}

/// Some(flag) when prev and next are same-minor patch versions and next
/// gained at least one capability. Mirrors `PatchVersionDriftFlag`.
pub fn patch_version_drift_flag(
    prev_ver: &str,
    next_ver: &str,
    added_caps: &CapabilitySet,
) -> Option<RiskFlag> {
    if !same_patch_pair(prev_ver, next_ver) || added_caps.is_empty() {
        return None;
    }
    Some(RiskFlag::new(
        Capability::PatchVersionDrift.name(),
        format!(
            "patch bump {}→{} grew {} — semver says patches don't change behaviour",
            prev_ver,
            next_ver,
            cap_list_string(added_caps)
        ),
        WEIGHT_PATCH_VERSION_DRIFT,
    ))
}

/// Some(flag) when dep is an npm package with a missing provenance
/// attestation. Mirrors `ProvenanceRiskFlag`.
pub fn provenance_risk_flag(dep: &Dependency) -> Option<RiskFlag> {
    if dep.ecosystem != Ecosystem::Npm || dep.provenance_status != "missing" {
        return None;
    }
    Some(RiskFlag::new(
        "provenance-missing",
        format!(
            "no SLSA provenance attestation in npm registry for {}@{}",
            dep.name, dep.version
        ),
        WEIGHT_PROVENANCE_MISSING,
    ))
}

/// True when prev and next share (major, minor) but differ in patch.
/// Mirrors `samePatchPair`.
fn same_patch_pair(prev: &str, next: &str) -> bool {
    let p = split_semver(prev);
    let n = split_semver(next);
    match (p, n) {
        (Some((pmaj, pmin, ppat)), Some((nmaj, nmin, npat))) => {
            pmaj == nmaj && pmin == nmin && ppat != npat
        }
        _ => false,
    }
}

/// Parse "X.Y.Z" / "vX.Y.Z" / "X.Y.Z-pre+meta" into (major, minor, patch).
/// Lightweight — enough for the patch comparison. Mirrors `splitSemver`.
fn split_semver(v: &str) -> Option<(i64, i64, i64)> {
    if v.is_empty() {
        return None;
    }
    let v = v.strip_prefix('v').unwrap_or(v);
    // Drop pre-release / build-metadata.
    let v = match v.find(['-', '+']) {
        Some(i) => &v[..i],
        None => v,
    };
    let parts: Vec<&str> = v.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parse_int(parts[0])?,
        parse_int(parts[1])?,
        parse_int(parts[2])?,
    ))
}

/// strconv.Atoi with a 1e9 cap to avoid overflow on pathological input;
/// the cap is monotonic so it doesn't affect real version ordering.
/// Mirrors `parseInt`.
fn parse_int(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    const MAX: i64 = 1_000_000_000;
    let mut n: i64 = 0;
    for r in s.chars() {
        if !r.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (r as i64 - '0' as i64);
        if n >= MAX {
            return Some(MAX);
        }
    }
    Some(n)
}

fn cap_list_string(caps: &CapabilitySet) -> String {
    caps.iter().map(|c| c.name()).collect::<Vec<_>>().join(", ")
}
