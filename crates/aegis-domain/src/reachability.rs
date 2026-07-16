//! Reachability-based risk suppression. Port of `internal/domain/reachability_apply.go`.
//!
//! When a dependency's code is provably unused (unreachable from project
//! source), non-install-phase risk flags get suppressed and their weight
//! removed from the score. Install-phase flags keep full weight: those
//! scripts run at install time, so reachability from user code is
//! irrelevant to their threat model. Opt-in — the default does nothing.

use crate::risk::RiskAssessment;

/// Classifies whether a dep is referenced by the user's project source.
/// Mirrors `Reachability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reachability {
    /// The default — analysis hasn't run, the language isn't supported,
    /// or parsing failed. Risk scoring treats this the same as Used
    /// (conservative).
    #[default]
    Unknown,
    /// At least one user-source file imports this dep.
    Used,
    /// Project source was scanned and no import matched. Risk score may
    /// be downgraded.
    Unused,
}

/// The exact text written into `suppress_by` when reachability
/// suppression fires. Constant so presenter / tests can match against it.
/// Mirrors `unreachableSuppressReason`.
pub const UNREACHABLE_SUPPRESS_REASON: &str = "unreachable from project source";

/// Returns a copy of `ra` with non-install flags marked `suppressed`
/// when `reach == Reachability::Unused` and `suppress` is true. Each
/// suppressed flag's weight is subtracted from the score (clamped at 0).
///
/// Install-phase flags keep their full weight regardless: those scripts
/// run at npm/pip/etc install time, reachability from user code is
/// irrelevant to their threat model.
///
/// `suppress` is sourced from the consumer (via env var or config) so the
/// default behaviour stays "don't change anything" — opt-in only.
///
/// `suppress_by` is set to a stable string so the presenter can
/// distinguish reachability-suppressed flags from allowlist-suppressed
/// ones if it wants to. Mirrors `RiskAssessment.DowngradeUnused`.
pub fn downgrade_unused(
    ra: &RiskAssessment,
    reach: Reachability,
    suppress: bool,
) -> RiskAssessment {
    if !suppress || reach != Reachability::Unused || ra.flags.is_empty() {
        return ra.clone();
    }
    let mut out = ra.clone();
    for f in &mut out.flags {
        if f.suppressed || is_install_phase_flag(&f.code) {
            continue;
        }
        f.suppressed = true;
        f.suppress_by = UNREACHABLE_SUPPRESS_REASON.to_string();
        out.score -= f.weight;
    }
    if out.score < 0 {
        out.score = 0;
    }
    out
}

/// Returns true for flag codes whose underlying capability runs at
/// install time (no user-code import path required). `downgrade_unused`
/// exempts these from suppression. Mirrors `isInstallPhaseFlag`.
fn is_install_phase_flag(code: &str) -> bool {
    matches!(
        code,
        "install-hook" | "install-hook-added" | "install-hook-changed" | "install-hook-suspicious"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskFlag;

    fn flag(code: &str, weight: i32) -> RiskFlag {
        RiskFlag {
            code: code.to_string(),
            detail: String::new(),
            weight,
            suppressed: false,
            suppress_by: String::new(),
        }
    }

    #[test]
    fn suppresses_non_install_flags() {
        let ra = RiskAssessment {
            score: 50,
            flags: vec![flag("shell-spawn", 20), flag("install-hook", 30)],
        };
        let out = downgrade_unused(&ra, Reachability::Unused, true);
        assert_eq!(out.score, 30, "only install-hook contributing");
        assert!(out.flags[0].suppressed, "shell-spawn should be suppressed");
        assert!(
            !out.flags[1].suppressed,
            "install-hook should NOT be suppressed (install-phase exempt)"
        );
        assert_eq!(out.flags[0].suppress_by, UNREACHABLE_SUPPRESS_REASON);
    }

    #[test]
    fn noop_when_suppress_false() {
        let ra = RiskAssessment {
            score: 20,
            flags: vec![flag("shell-spawn", 20)],
        };
        let out = downgrade_unused(&ra, Reachability::Unused, false);
        assert_eq!(out.score, 20);
        assert!(!out.flags[0].suppressed);
    }

    #[test]
    fn noop_when_reachable() {
        let ra = RiskAssessment {
            score: 20,
            flags: vec![flag("shell-spawn", 20)],
        };
        let out = downgrade_unused(&ra, Reachability::Used, true);
        assert_eq!(out.score, 20);
        assert!(!out.flags[0].suppressed);
    }

    #[test]
    fn skips_already_suppressed() {
        let ra = RiskAssessment {
            score: 0,
            flags: vec![RiskFlag {
                code: "shell-spawn".to_string(),
                detail: String::new(),
                weight: 20,
                suppressed: true,
                suppress_by: "allowlist".to_string(),
            }],
        };
        let out = downgrade_unused(&ra, Reachability::Unused, true);
        assert_eq!(
            out.flags[0].suppress_by, "allowlist",
            "already-suppressed flag must keep its allowlist reason"
        );
        assert_eq!(out.score, 0);
    }

    #[test]
    fn score_clamps_at_zero() {
        // weights exceed the stored score → clamp instead of going negative.
        let ra = RiskAssessment {
            score: 10,
            flags: vec![flag("shell-spawn", 20), flag("net-egress", 10)],
        };
        let out = downgrade_unused(&ra, Reachability::Unused, true);
        assert_eq!(out.score, 0);
        assert!(out.flags.iter().all(|f| f.suppressed));
    }

    #[test]
    fn unknown_is_default_and_noop() {
        assert_eq!(Reachability::default(), Reachability::Unknown);
        let ra = RiskAssessment {
            score: 20,
            flags: vec![flag("shell-spawn", 20)],
        };
        let out = downgrade_unused(&ra, Reachability::Unknown, true);
        assert_eq!(out.score, 20);
        assert!(!out.flags[0].suppressed);
    }
}
