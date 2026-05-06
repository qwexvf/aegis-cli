package domain

import "strings"

// ApplyAllowlist returns a copy of the assessment in which any flag
// matched by the AllowSet is marked Suppressed (with SuppressBy = the
// rule's Reason) and its Weight is removed from the aggregate Score.
//
// The original assessment is unchanged; the result is a new value.
//
// Mapping flag codes → Capability happens here (not in AllowSet) so
// the allowlist's domain remains a pure data structure unaware of
// the risk engine's flag taxonomy. If a flag has no Capability
// equivalent (e.g. "size-anomaly", which is a drift-only signal that
// can't be allowlisted by Capability), it is never suppressed.
func (ra RiskAssessment) ApplyAllowlist(eco Ecosystem, name, version string, set AllowSet) RiskAssessment {
	if set.Len() == 0 || len(ra.Flags) == 0 {
		return ra
	}
	out := RiskAssessment{
		Score: ra.Score,
		Flags: make([]RiskFlag, len(ra.Flags)),
	}
	copy(out.Flags, ra.Flags)

	for i := range out.Flags {
		f := &out.Flags[i]
		if f.Suppressed {
			continue // already suppressed; don't double-count
		}
		cap, ok := capabilityForFlag(*f)
		if !ok {
			continue
		}
		matched, rule := set.Suppresses(eco, name, version, cap)
		if !matched {
			continue
		}
		f.Suppressed = true
		f.SuppressBy = rule.Reason
		out.Score -= f.Weight
	}
	if out.Score < 0 {
		out.Score = 0
	}
	return out
}

// capabilityForFlag maps a RiskFlag.Code to the Capability the
// allowlist key uses. The mapping is intentionally explicit (not a
// table-driven approach) so changes to flag codes force compile-time
// updates here.
func capabilityForFlag(f RiskFlag) (Capability, bool) {
	switch f.Code {
	case "install-hook", "install-hook-added", "install-hook-changed":
		return CapInstallHookExec, true
	case "shell-spawn":
		return CapShellSpawn, true
	case "dynamic-eval":
		return CapDynamicEval, true
	case "base64-decode":
		return CapBase64Decode, true
	case "net-egress":
		return CapNetEgress, true
	case "env-cred-read":
		return CapEnvRead, true
	case "fs-write-outside-root":
		return CapFSWriteOutsideRoot, true
	case "raw-ip-literal":
		return CapRawIPLiteral, true
	case "capability-added":
		// drift flag — Capability name is embedded in Detail like:
		//   "new capability since prior version: shell-spawn"
		return parseCapabilityFromDetail(f.Detail)
	}
	// "size-anomaly" and unknown codes: not allowlist-able.
	return 0, false
}

// parseCapabilityFromDetail extracts the trailing capability token
// from a "capability-added" drift flag's Detail string.
//
// The prefix is owned by risk.go (capabilityAddedDetailPrefix); we
// reference the constant rather than duplicating the string, so the
// producer and the parser cannot drift apart.
func parseCapabilityFromDetail(detail string) (Capability, bool) {
	_, after, ok := strings.Cut(detail, capabilityAddedDetailPrefix)
	if !ok {
		return 0, false
	}
	name := strings.TrimSpace(after)
	if c, ok := capabilityNameLookup[name]; ok {
		return c, true
	}
	return 0, false
}

// capabilityNameLookup is a name → Capability table, populated once
// at package init. Replaces the O(N) loop that previously walked
// AllCapabilities() on every Detail parse.
var capabilityNameLookup = func() map[string]Capability {
	m := make(map[string]Capability, len(AllCapabilities()))
	for _, c := range AllCapabilities() {
		m[c.String()] = c
	}
	return m
}()
