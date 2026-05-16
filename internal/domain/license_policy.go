package domain

import "strings"

// LicensePolicy is an optional SPDX-based gate applied by `aegis ci`.
// Exactly one mode is active: if Allow is non-empty, only those SPDX
// identifiers are permitted (allowlist mode); if Deny is non-empty,
// those identifiers are rejected (denylist mode). Both empty means no
// policy — every license (including unknown) passes.
type LicensePolicy struct {
	Allow []string // SPDX IDs, e.g. ["MIT", "Apache-2.0"]
	Deny  []string // SPDX IDs, e.g. ["GPL-3.0", "AGPL-3.0"]
}

// Empty reports whether no policy is configured.
func (p LicensePolicy) Empty() bool {
	return len(p.Allow) == 0 && len(p.Deny) == 0
}

// Check returns a non-empty violation reason when license violates the
// policy. Empty string means the dep passes. Comparison is
// case-insensitive so "MIT" and "mit" both match.
//
// In allowlist mode, an empty license string is treated as a violation
// ("license unknown") so packages that never had a license fetched
// don't silently slip through a strict policy. In denylist mode, an
// empty license is treated as passing (can't deny what isn't known).
func (p LicensePolicy) Check(license string) string {
	if p.Empty() {
		return ""
	}
	lic := strings.TrimSpace(license)

	if len(p.Deny) > 0 {
		for _, d := range p.Deny {
			if strings.EqualFold(lic, d) {
				return "denied license: " + lic
			}
		}
		return ""
	}

	// allowlist mode
	if lic == "" {
		return "license unknown — not in allow-list"
	}
	for _, a := range p.Allow {
		if strings.EqualFold(lic, a) {
			return ""
		}
	}
	return "license " + lic + " not in allow-list"
}
