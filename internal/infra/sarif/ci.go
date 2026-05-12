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
	rules := make([]Rule, 0, len(caps))
	for _, c := range caps {
		rules = append(rules, Rule{
			ID:               c.String(),
			ShortDescription: Message{Text: c.Description()},
			DefaultConfig:    &RuleDefaultConfig{Level: "warning"},
		})
	}
	return rules
}()

// CIToSARIF converts a CIResult (package scan) to a SARIF 2.1.0 Log.
// Each risky dependency becomes one or more SARIF results (one per
// capability flag). toolVersion is stamped into the tool driver.
func CIToSARIF(result usecase.CIResult, toolVersion string) Log {
	results := make([]Result, 0, len(result.Findings))
	for _, f := range result.Findings {
		for _, flag := range f.Risk.Flags {
			if flag.Suppressed {
				// Include suppressed flags so output is transparent,
				// but mark them with suppressions[].
				r := buildCIResult(f.Dep, flag)
				r.Suppressions = []Suppression{{
					Kind:          "external",
					Justification: flag.SuppressBy,
				}}
				results = append(results, r)
				continue
			}
			results = append(results, buildCIResult(f.Dep, flag))
		}
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

func buildCIResult(dep domain.Dependency, flag domain.RiskFlag) Result {
	return Result{
		RuleID:  flag.Code,
		Level:   capLevelFromWeight(flag.Weight),
		Message: Message{Text: fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, flag.Detail)},
		Locations: []Location{{
			PhysicalLocation: PhysicalLocation{
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
