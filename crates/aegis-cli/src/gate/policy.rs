//! Verdict → action. A pure table, so the whole policy is testable as a
//! cross-product with no I/O.
//!
//! The gate is **fail-closed**: anything we could not verify blocks, because
//! making the scanner unreachable is otherwise a complete bypass for exactly
//! the network-positioned adversary this tool models. That is stricter than
//! the Go original, which proceeds on resolve errors, check errors and
//! timeouts alike.
//!
//! Two escape hatches keep that from being unusable, and every blocking
//! message names them: `--allow-unchecked` for "I know I'm offline", and
//! `AEGIS_NO_GATE=1` to skip the gate entirely. A gate with no visible bypass
//! gets uninstalled, and an uninstalled gate protects nobody.

use aegis_domain::VerdictKind;

/// Why a spec could not be given a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unchecked {
    /// The registry has no such package — the install would fail anyway, and
    /// a typo'd name is squattable tomorrow.
    NotFound,
    /// We could not reach the registry or the advisory feed.
    Unreachable(String),
    /// Fetched, but the scan itself failed.
    ScanFailed(String),
}

/// What the gate decided about one spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Verified and acceptable.
    Proceed,
    /// Verified and over the threshold.
    Block,
    /// Not verified; blocked because the gate is fail-closed.
    BlockUnchecked,
    /// Not verified, but allowed — `--allow-unchecked`, or our own argv parse
    /// was unreliable.
    WarnUnchecked,
}

impl Action {
    pub(crate) fn blocks(&self) -> bool {
        matches!(self, Action::Block | Action::BlockUnchecked)
    }
}

/// Inputs that are the same for every spec in one invocation.
#[derive(Debug, Clone)]
pub(crate) struct PolicyCtx {
    /// Verdict at or above which a *verified* package is refused.
    pub fail_on: VerdictKind,
    /// `--allow-unchecked`: downgrade every unverified block to a warning.
    pub allow_unchecked: bool,
    /// Our argv walk met an unknown flag, so a "package" we collected may
    /// really be that flag's value. Blocking an install because *we*
    /// mis-parsed is worse than missing one, so unverified specs only warn.
    pub uncertain_parse: bool,
}

/// A verified verdict → an action.
pub(crate) fn evaluate(v: VerdictKind, ctx: &PolicyCtx) -> Action {
    if v >= ctx.fail_on {
        Action::Block
    } else {
        Action::Proceed
    }
}

/// An unverifiable spec → an action.
pub(crate) fn evaluate_unchecked(_why: &Unchecked, ctx: &PolicyCtx) -> Action {
    if ctx.allow_unchecked || ctx.uncertain_parse {
        Action::WarnUnchecked
    } else {
        Action::BlockUnchecked
    }
}

impl std::fmt::Display for Unchecked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unchecked::NotFound => write!(f, "not found in registry"),
            Unchecked::Unreachable(e) => write!(f, "could not verify: {e}"),
            Unchecked::ScanFailed(e) => write!(f, "scan failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> PolicyCtx {
        PolicyCtx {
            fail_on: VerdictKind::Block,
            allow_unchecked: false,
            uncertain_parse: false,
        }
    }

    #[test]
    fn verified_verdicts_compare_against_the_threshold() {
        let c = ctx();
        assert_eq!(evaluate(VerdictKind::Safe, &c), Action::Proceed);
        assert_eq!(evaluate(VerdictKind::Review, &c), Action::Proceed);
        assert_eq!(evaluate(VerdictKind::Prompt, &c), Action::Proceed);
        assert_eq!(evaluate(VerdictKind::Block, &c), Action::Block);

        // A lower threshold catches more.
        let strict = PolicyCtx {
            fail_on: VerdictKind::Review,
            ..ctx()
        };
        assert_eq!(evaluate(VerdictKind::Review, &strict), Action::Block);
        assert_eq!(evaluate(VerdictKind::Safe, &strict), Action::Proceed);
    }

    #[test]
    fn unverifiable_specs_block_by_default() {
        // The whole point of fail-closed: an unreachable scanner must not be
        // a silent bypass.
        let c = ctx();
        for why in [
            Unchecked::NotFound,
            Unchecked::Unreachable("dns".into()),
            Unchecked::ScanFailed("corrupt tarball".into()),
        ] {
            assert_eq!(evaluate_unchecked(&why, &c), Action::BlockUnchecked);
        }
    }

    #[test]
    fn allow_unchecked_downgrades_to_a_warning() {
        let c = PolicyCtx {
            allow_unchecked: true,
            ..ctx()
        };
        assert_eq!(
            evaluate_unchecked(&Unchecked::Unreachable("offline".into()), &c),
            Action::WarnUnchecked
        );
        // It does NOT rescue a package we successfully verified as bad.
        assert_eq!(evaluate(VerdictKind::Block, &c), Action::Block);
    }

    #[test]
    fn an_uncertain_argv_parse_never_blocks_on_unverified() {
        // We may have invented a package out of an unknown flag's value.
        let c = PolicyCtx {
            uncertain_parse: true,
            ..ctx()
        };
        assert_eq!(
            evaluate_unchecked(&Unchecked::NotFound, &c),
            Action::WarnUnchecked
        );
        // But a package that really did scan as malicious still blocks.
        assert_eq!(evaluate(VerdictKind::Block, &c), Action::Block);
    }

    #[test]
    fn blocks_is_true_for_both_block_kinds() {
        assert!(Action::Block.blocks());
        assert!(Action::BlockUnchecked.blocks());
        assert!(!Action::Proceed.blocks());
        assert!(!Action::WarnUnchecked.blocks());
    }
}
