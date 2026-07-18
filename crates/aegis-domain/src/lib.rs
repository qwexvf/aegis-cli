//! Pure domain core for the aegis supply-chain scanner.
//!
//! Clean-room Rust port of the Go `internal/domain` package — risk
//! scoring, capabilities, verdicts, and the supporting value types.
//! No I/O, no external crates: the scoring is a pure function of its
//! inputs, exactly like the Go original.

pub mod advisory;
pub mod allowlist;
pub mod capability;
pub mod fix;
pub mod reachability;
pub mod risk;
mod semver;
pub mod types;

pub use advisory::{max_severity, Advisory, AdvisoryQuery, Severity};
pub use allowlist::{
    apply_allowlist, builtin_allow_rules, AllowRule, AllowSet, Match, MatchKind,
    ALLOWLIST_SUPPRESS_PREFIX,
};
pub use capability::{Capability, CapabilitySet, ALL_CAPABILITIES};
pub use fix::{build_fix_plan, compare_fix_version, upgrade_command, FixItem};
pub use reachability::{downgrade_unused, Reachability, UNREACHABLE_SUPPRESS_REASON};
pub use risk::{
    downgrade_verdict, drift_score, patch_version_drift_flag, provenance_risk_flag, risk_score,
    verdict, verdict_for_advisories, RiskAssessment, RiskFlag, VerdictKind,
    VERDICT_THRESHOLD_BLOCK, VERDICT_THRESHOLD_PROMPT, VERDICT_THRESHOLD_REVIEW,
};
pub use types::{Dependency, Ecosystem, Fingerprint, HookPhase, InstallHook};

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzed(caps: &[Capability]) -> Fingerprint {
        Fingerprint {
            analyzed: true,
            capabilities: CapabilitySet::new(caps.iter().copied()),
            ..Default::default()
        }
    }

    #[test]
    fn capability_names_are_stable() {
        assert_eq!(Capability::ShellSpawn.name(), "shell-spawn");
        // the one name that intentionally diverges from the variant.
        assert_eq!(Capability::TarballDrift.name(), "tarball-source-drift");
        assert_eq!(Capability::HardcodedSecret.name(), "hardcoded-secret");
        assert_eq!(ALL_CAPABILITIES.len(), 23);
    }

    #[test]
    fn capability_set_dedups_and_sorts() {
        let s = CapabilitySet::new([
            Capability::NetEgress,
            Capability::ShellSpawn,
            Capability::NetEgress,
        ]);
        assert_eq!(s.len(), 2);
        // ShellSpawn declared before NetEgress → sorts first.
        let names: Vec<_> = s.iter().map(|c| c.name()).collect();
        assert_eq!(names, ["shell-spawn", "net-egress"]);
    }

    #[test]
    fn difference_preserves_order() {
        let a = CapabilitySet::new([Capability::ShellSpawn, Capability::NetEgress]);
        let b = CapabilitySet::new([Capability::NetEgress]);
        let d = a.difference(&b);
        assert_eq!(d.len(), 1);
        assert!(d.has(Capability::ShellSpawn));
    }

    #[test]
    fn nil_and_empty_fingerprints_score_zero() {
        assert_eq!(risk_score(None).score, 0);
        assert_eq!(risk_score(Some(&Fingerprint::default())).score, 0);
    }

    #[test]
    fn heuristic_only_ecosystem_still_scores() {
        // not analyzed, but carries a capability → must score.
        let fp = Fingerprint {
            analyzed: false,
            capabilities: CapabilitySet::new([Capability::InstallHookSuspicious]),
            ..Default::default()
        };
        assert_eq!(
            risk_score(Some(&fp)).score,
            risk::WEIGHT_INSTALL_HOOK_SUSPICIOUS
        );
    }

    #[test]
    fn known_malware_ioc_blocks_alone() {
        let fp = analyzed(&[Capability::KnownMalwareIoc]);
        let ra = risk_score(Some(&fp));
        assert_eq!(ra.score, 100);
        assert_eq!(verdict(&ra, &RiskAssessment::default()), VerdictKind::Block);
    }

    #[test]
    fn install_hook_plus_suspicious_stacks() {
        let mut fp = analyzed(&[Capability::InstallHookSuspicious]);
        fp.hooks.push(InstallHook {
            phase: HookPhase::PostInstall,
            source: "scripts.postinstall".into(),
            sha256: String::new(),
        });
        let ra = risk_score(Some(&fp));
        assert_eq!(
            ra.score,
            risk::WEIGHT_INSTALL_HOOK + risk::WEIGHT_INSTALL_HOOK_SUSPICIOUS
        );
        assert_eq!(verdict(&ra, &RiskAssessment::default()), VerdictKind::Block);
    }

    #[test]
    fn env_read_only_flags_credential_shaped_names() {
        let mut fp = analyzed(&[Capability::EnvRead]);
        fp.env_reads = vec!["NODE_ENV".into(), "HOME".into()];
        assert_eq!(
            risk_score(Some(&fp)).score,
            0,
            "boring env vars don't score"
        );

        fp.env_reads.push("aws_secret_access_key".into()); // lowercase → still matches
        assert_eq!(risk_score(Some(&fp)).score, risk::WEIGHT_ENV_CRED_READ);
    }

    #[test]
    fn verdict_thresholds() {
        let at = |score: i32| {
            let ra = RiskAssessment {
                score,
                flags: vec![],
            };
            verdict(&ra, &RiskAssessment::default())
        };
        assert_eq!(at(0), VerdictKind::Safe);
        assert_eq!(at(20), VerdictKind::Safe);
        assert_eq!(at(21), VerdictKind::Review);
        assert_eq!(at(60), VerdictKind::Review);
        assert_eq!(at(61), VerdictKind::Prompt);
        assert_eq!(at(99), VerdictKind::Prompt);
        assert_eq!(at(100), VerdictKind::Block);
    }

    #[test]
    fn verdict_uses_max_of_risk_and_drift() {
        let risk = RiskAssessment {
            score: 10,
            flags: vec![],
        };
        let drift = RiskAssessment {
            score: 100,
            flags: vec![],
        };
        assert_eq!(verdict(&risk, &drift), VerdictKind::Block);
    }

    #[test]
    fn drift_flags_added_hook_and_capability() {
        let prev = analyzed(&[]);
        let mut next = analyzed(&[Capability::NetEgress]);
        next.hooks.push(InstallHook {
            phase: HookPhase::PostInstall,
            source: "scripts.postinstall".into(),
            sha256: "abc".into(),
        });
        let ra = drift_score(Some(&prev), Some(&next));
        // one new hook (30) + one new capability (15).
        assert_eq!(
            ra.score,
            risk::WEIGHT_INSTALL_HOOK + risk::WEIGHT_CAPABILITY_ADD
        );
    }

    #[test]
    fn drift_requires_both_analyzed() {
        let prev = Fingerprint {
            analyzed: false,
            ..Default::default()
        };
        let next = analyzed(&[Capability::KnownMalwareIoc]);
        assert_eq!(drift_score(Some(&prev), Some(&next)).score, 0);
    }

    #[test]
    fn patch_drift_only_within_same_minor() {
        let caps = CapabilitySet::new([Capability::NetEgress]);
        assert!(patch_version_drift_flag("1.2.3", "1.2.4", &caps).is_some());
        assert!(patch_version_drift_flag("1.2.3", "1.3.0", &caps).is_none());
        assert!(patch_version_drift_flag("1.2.3", "1.2.3", &caps).is_none());
        // strips v-prefix and pre-release.
        assert!(patch_version_drift_flag("v1.2.3-beta", "1.2.4", &caps).is_some());
        // no added caps → no flag.
        assert!(patch_version_drift_flag("1.2.3", "1.2.4", &CapabilitySet::default()).is_none());
    }

    #[test]
    fn provenance_flag_only_for_missing_npm() {
        let miss = Dependency {
            ecosystem: Ecosystem::Npm,
            name: "lodash".into(),
            version: "4.17.21".into(),
            provenance_status: "missing".into(),
            ..Default::default()
        };
        assert!(provenance_risk_flag(&miss).is_some());

        let other = Dependency {
            ecosystem: Ecosystem::PyPI,
            ..miss.clone()
        };
        assert!(provenance_risk_flag(&other).is_none());

        let attested = Dependency {
            provenance_status: String::new(),
            ..miss
        };
        assert!(provenance_risk_flag(&attested).is_none());
    }
}
