// Package domain — FixPlan computes the minimal version bumps required
// to resolve known vulnerabilities across a snapshot. Pure function over
// (Snapshot + Advisories). No I/O.
//
// Algorithm:
//   - Group all dep advisories by (ecosystem, name).
//   - For each group, pick the highest FixedIn version (lexicographic
//     ordering — good enough for the npm/cargo/go semver-like strings
//     that dominate; PEP 440 / Maven coordinates are best-effort).
//   - The resulting target is the smallest single upgrade that clears
//     every advisory whose FixedIn is set.
//   - Advisories without FixedIn (rare — OSV usually has it) remain
//     "unresolved" and are surfaced separately so the user can decide
//     to vendor-patch or remove the dep.
package domain

import (
	"fmt"
	"strings"
)

// FixPlan is the result of BuildFixPlan: one entry per affected dep.
type FixPlan struct {
	Items []FixItem
}

// Empty reports whether the plan has nothing to do.
func (p FixPlan) Empty() bool {
	return len(p.Items) == 0
}

// FixItem is one dep that has at least one known vulnerability and a
// concrete upgrade target. Resolved is the subset of advisories whose
// FixedIn the upgrade clears; Unresolved are advisories with no
// upstream fix metadata.
type FixItem struct {
	Dep                  Dependency
	TargetVersion        string // "" when no FixedIn data on any advisory
	ResolvedAdvisories   []Advisory
	UnresolvedAdvisories []Advisory
}

// BuildFixPlan computes a FixPlan from a snapshot. Deps with no
// advisories are skipped. VEX-suppressed advisories are ignored so the
// fix planner doesn't propose upgrades for cleared CVEs.
func BuildFixPlan(snap Snapshot) FixPlan {
	var out FixPlan
	for _, d := range snap.Deps {
		if len(d.Advisories) == 0 {
			continue
		}
		var resolved, unresolved []Advisory
		var target string
		for _, a := range d.Advisories {
			if a.VEXSuppressed || a.FunctionUnreachable {
				continue
			}
			if a.FixedIn == "" {
				unresolved = append(unresolved, a)
				continue
			}
			resolved = append(resolved, a)
			if target == "" || compareFixVersion(a.FixedIn, target) > 0 {
				target = a.FixedIn
			}
		}
		if len(resolved) == 0 && len(unresolved) == 0 {
			continue
		}
		out.Items = append(out.Items, FixItem{
			Dep:                  d,
			TargetVersion:        target,
			ResolvedAdvisories:   resolved,
			UnresolvedAdvisories: unresolved,
		})
	}
	return out
}

// compareFixVersion compares two version strings. Returns -1 / 0 / 1.
// MVP: lexicographic with numeric-aware segment compare. Handles common
// semver shapes ("1.2.3", "1.2.10", "v1.2.3") correctly without pulling
// in golang.org/x/mod/semver. Falls back to byte compare for shapes
// outside semver (PEP 440 epoch markers, Maven qualifier strings).
func compareFixVersion(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ax, aIsNum := parseLeadingInt(as[i])
		bx, bIsNum := parseLeadingInt(bs[i])
		if aIsNum && bIsNum {
			if ax != bx {
				if ax < bx {
					return -1
				}
				return 1
			}
			continue
		}
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// parseLeadingInt reads the leading numeric prefix of s. Returns (n,
// true) when s starts with at least one digit; (0, false) otherwise.
// Used by compareFixVersion to handle "1.2.10" > "1.2.9" correctly.
func parseLeadingInt(s string) (int, bool) {
	n := 0
	any := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		any = true
	}
	return n, any
}

// UpgradeCommand returns the ecosystem-appropriate upgrade shell command
// for dep. When targetVersion is non-empty, the command pins to that
// version; otherwise it falls back to the ecosystem's "latest" verb.
// Returns "" when no command shape is known.
func UpgradeCommand(dep Dependency, targetVersion string) string {
	name := dep.Name
	pinned := targetVersion != ""
	switch dep.Ecosystem {
	case EcoNpm:
		if pinned {
			return fmt.Sprintf("npm install %s@%s", name, targetVersion)
		}
		return fmt.Sprintf("npm install %s@latest", name)
	case EcoPyPI:
		if pinned {
			return fmt.Sprintf("pip install %s==%s", name, targetVersion)
		}
		return fmt.Sprintf("pip install --upgrade %s", name)
	case EcoRubyGems:
		if pinned {
			return fmt.Sprintf("bundle update --conservative %s  # target: %s", name, targetVersion)
		}
		return fmt.Sprintf("bundle update %s", name)
	case EcoCrates:
		cratesName := strings.ReplaceAll(name, "/", "-")
		if pinned {
			return fmt.Sprintf("cargo update -p %s --precise %s", cratesName, targetVersion)
		}
		return fmt.Sprintf("cargo update -p %s", cratesName)
	case EcoGo:
		if pinned {
			return fmt.Sprintf("go get %s@%s", name, targetVersion)
		}
		return fmt.Sprintf("go get %s@latest", name)
	case EcoMaven:
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			if pinned {
				return fmt.Sprintf("mvn versions:set-property -Dproperty=%s.version -DnewVersion=%s", parts[1], targetVersion)
			}
			return fmt.Sprintf("mvn versions:use-latest-versions -Dincludes=%s:%s", parts[0], parts[1])
		}
	case EcoPackagist:
		if pinned {
			return fmt.Sprintf("composer require %s:%s", name, targetVersion)
		}
		return fmt.Sprintf("composer update %s", name)
	case EcoNuGet:
		if pinned {
			return fmt.Sprintf("dotnet add package %s --version %s", name, targetVersion)
		}
		return fmt.Sprintf("dotnet add package %s", name)
	case EcoGleam:
		return "gleam deps update"
	}
	return ""
}
