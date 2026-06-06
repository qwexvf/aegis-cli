package sarif

import (
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// ciRules maps aegis capability strings to SARIF rule definitions.
// Generated from domain.AllCapabilities() at init; extended as new
// capabilities are added.
var ciRules = func() []Rule {
	caps := domain.AllCapabilities()
	rules := make([]Rule, 0, len(caps)+len(syntheticCIRules))
	for _, c := range caps {
		rules = append(rules, Rule{
			ID:               c.String(),
			ShortDescription: Message{Text: c.Description()},
			DefaultConfig:    &RuleDefaultConfig{Level: "warning"},
		})
	}
	rules = append(rules, syntheticCIRules...)
	return rules
}()

// syntheticCIRules cover findings that cross the fail-on threshold
// without a capability flag — known CVEs, license-policy hits,
// deprecated packages, and deps that blocked for any other reason
// (e.g. a registry fetch failure). Without these, such findings
// appear in `ci --json` but produce zero SARIF results and vanish
// from the GitHub Security tab.
var syntheticCIRules = []Rule{
	{ID: ruleVulnerableDep, ShortDescription: Message{Text: "dependency has a known security advisory (CVE/GHSA)"}, DefaultConfig: &RuleDefaultConfig{Level: "error"}},
	{ID: ruleLicenseViolation, ShortDescription: Message{Text: "dependency license violates the configured policy"}, DefaultConfig: &RuleDefaultConfig{Level: "error"}},
	{ID: ruleDeprecatedPkg, ShortDescription: Message{Text: "dependency is marked deprecated by its registry"}, DefaultConfig: &RuleDefaultConfig{Level: "warning"}},
	{ID: ruleBlockedDep, ShortDescription: Message{Text: "dependency crossed the fail-on threshold"}, DefaultConfig: &RuleDefaultConfig{Level: "error"}},
	{ID: ruleUnscanned, ShortDescription: Message{Text: "dependency could not be scanned (fetch failure / offline) and the run is fail-closed"}, DefaultConfig: &RuleDefaultConfig{Level: "error"}},
}

const (
	ruleVulnerableDep    = "vulnerable-dependency"
	ruleLicenseViolation = "license-violation"
	ruleDeprecatedPkg    = "deprecated-package"
	ruleBlockedDep       = "blocked-dependency"
	ruleUnscanned        = "unscanned"
)

// CIToSARIF converts a CIResult (package scan) to a SARIF 2.1.0 Log.
// Each risky dependency becomes one or more SARIF results (one per
// capability flag). toolVersion is stamped into the tool driver.
func CIToSARIF(result usecase.CIResult, toolVersion string) Log {
	results := make([]Result, 0, len(result.Findings))
	for _, f := range result.Findings {
		results = append(results, ciResultsForFinding(f)...)
	}

	return Log{
		Version: Version210,
		Schema:  schema210,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           "aegis-cli",
				Version:        toolVersion,
				InformationURI: "https://github.com/qwexvf/aegis-cli",
				Rules:          ciRules,
			}},
			Results: results,
		}},
	}
}

// ciResultsForFinding expands one CI finding into its SARIF results.
// It covers every way a dep can cross the threshold — capability
// flags (risk + drift), known advisories, license violations, and
// deprecation — and guarantees at least one result so a finding can
// never be present in --json yet absent from --sarif.
func ciResultsForFinding(f usecase.CIFinding) []Result {
	var out []Result

	flagResult := func(flag domain.RiskFlag) {
		r := buildCIResult(f.Dep, flag)
		if flag.Suppressed {
			// Include suppressed flags so output is transparent,
			// but mark them with suppressions[].
			r.Suppressions = []Suppression{{Kind: "external", Justification: flag.SuppressBy}}
		}
		out = append(out, r)
	}
	for _, flag := range f.Risk.Flags {
		flagResult(flag)
	}
	// Drift flags (baseline mode) were previously dropped entirely.
	for _, flag := range f.Drift.Flags {
		flagResult(flag)
	}

	// Known advisories — only the active subset (VEX / reachability
	// suppressed advisories are excluded from the SARIF, matching how
	// they're excluded from scoring).
	for _, adv := range f.Dep.Advisories {
		if adv.VEXSuppressed || adv.FunctionUnreachable {
			continue
		}
		out = append(out, syntheticResult(f.Dep, ruleVulnerableDep,
			levelFromSeverity(adv.Severity),
			fmt.Sprintf("%s: %s (%s)", adv.ID, adv.Summary, adv.Severity)))
	}

	if f.LicenseViolation != "" {
		out = append(out, syntheticResult(f.Dep, ruleLicenseViolation, "error", f.LicenseViolation))
	}
	if f.Deprecated {
		msg := "package is deprecated"
		if f.DeprecatedReason != "" {
			msg += ": " + f.DeprecatedReason
		}
		out = append(out, syntheticResult(f.Dep, ruleDeprecatedPkg, "warning", msg))
	}

	// Fallback: the finding crossed the threshold but produced no
	// flags, advisories, license, or deprecation result (e.g. a
	// registry fetch failure forced a block). Emit a synthetic result
	// so it stays visible.
	if len(out) == 0 {
		out = append(out, syntheticResult(f.Dep, ruleBlockedDep, "error",
			fmt.Sprintf("blocked (verdict=%s) with no detailed signal", f.Verdict)))
	}
	return out
}

// levelFromSeverity maps an advisory severity onto a SARIF level.
func levelFromSeverity(s domain.Severity) string {
	switch s {
	case domain.SevCritical, domain.SevHigh:
		return "error"
	case domain.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// syntheticResult builds a SARIF result for a finding dimension that
// isn't a capability flag (advisory, license, deprecation, fallback).
func syntheticResult(dep domain.Dependency, ruleID, level, detail string) Result {
	return Result{
		RuleID:  ruleID,
		Level:   level,
		Message: Message{Text: fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, detail)},
		Locations: []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       dep.Name + "@" + dep.Version,
					URIBaseID: "%PKGROOT%",
				},
			},
			LogicalLocations: []LogicalLocation{{
				FullyQualifiedName: string(dep.Ecosystem) + ":" + dep.Name + "@" + dep.Version,
				Kind:               "package",
			}},
		}},
	}
}

func buildCIResult(dep domain.Dependency, flag domain.RiskFlag) Result {
	return Result{
		RuleID:  flag.Code,
		Level:   capLevelFromWeight(flag.Weight),
		Message: Message{Text: fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, flag.Detail)},
		Locations: []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       dep.Name + "@" + dep.Version,
					URIBaseID: "%PKGROOT%",
				},
			},
			LogicalLocations: []LogicalLocation{{
				FullyQualifiedName: string(dep.Ecosystem) + ":" + dep.Name + "@" + dep.Version,
				Kind:               "package",
			}},
		}},
	}
}

// capLevelFromWeight maps a RiskFlag weight to a SARIF level.
// Weights ≥ 60 → error (block/critical), 30–59 → warning, < 30 → note.
func capLevelFromWeight(w int) string {
	switch {
	case w >= 60:
		return "error"
	case w >= 30:
		return "warning"
	default:
		return "note"
	}
}
