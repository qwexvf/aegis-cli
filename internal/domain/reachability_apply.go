package domain

// DowngradeUnused returns a copy of ra with non-install flags marked
// Suppressed when reach == ReachabilityUnused and suppress is true.
//
// Install-phase flags ("install-hook" and friends) keep their full
// weight regardless: those scripts run at npm/pip/etc install time,
// reachability from user code is irrelevant to their threat model.
//
// suppress is sourced from the consumer (via env var or config) so
// the default behaviour stays "don't change anything" — opt-in only.
//
// SuppressBy is set to a stable string so the presenter can
// distinguish reachability-suppressed flags from allowlist-suppressed
// ones if it wants to.
func (ra RiskAssessment) DowngradeUnused(reach Reachability, suppress bool) RiskAssessment {
	if !suppress || reach != ReachabilityUnused || len(ra.Flags) == 0 {
		return ra
	}
	out := RiskAssessment{
		Score: ra.Score,
		Flags: make([]RiskFlag, len(ra.Flags)),
	}
	copy(out.Flags, ra.Flags)
	for i := range out.Flags {
		f := &out.Flags[i]
		if f.Suppressed || isInstallPhaseFlag(f.Code) {
			continue
		}
		f.Suppressed = true
		f.SuppressBy = unreachableSuppressReason
		out.Score -= f.Weight
	}
	if out.Score < 0 {
		out.Score = 0
	}
	return out
}

// unreachableSuppressReason is the exact text written into
// SuppressBy when reachability suppression fires. Constant so
// presenter / tests can match against it.
const unreachableSuppressReason = "unreachable from project source"

// isInstallPhaseFlag returns true for flag codes whose underlying
// capability runs at install time (no user-code import path
// required). DowngradeUnused exempts these from suppression.
func isInstallPhaseFlag(code string) bool {
	switch code {
	case "install-hook",
		"install-hook-added",
		"install-hook-changed",
		"install-hook-suspicious":
		return true
	}
	return false
}
