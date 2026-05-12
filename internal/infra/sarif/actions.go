package sarif

import (
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// actionsRules is the complete rule set for the Actions scanner. Every
// WorkflowFindingKind that Analyze() can emit must have an entry here.
var actionsRules = []Rule{
	{
		ID:               domain.FindingUnpinnedRef.String(),
		ShortDescription: Message{Text: "Action ref not pinned to a commit SHA"},
		FullDescription:  &Message{Text: "Using a tag or branch ref means the action can be retargeted by the owner without changing your workflow. Pin to a 40-character commit SHA."},
		DefaultConfig:    &RuleDefaultConfig{Level: "warning"},
	},
	{
		ID:               domain.FindingSuspiciousRun.String(),
		ShortDescription: Message{Text: "Suspicious run-script pattern"},
		FullDescription:  &Message{Text: "The run: body matches a known malware-distribution pattern (curl|sh, base64-decode-and-exec, raw IP literal, or known exfil destination)."},
		DefaultConfig:    &RuleDefaultConfig{Level: "error"},
	},
	{
		ID:               domain.FindingPullRequestTargetCheckout.String(),
		ShortDescription: Message{Text: "pull_request_target workflow checks out PR head"},
		FullDescription:  &Message{Text: "Checking out the PR contributor's code inside a pull_request_target job grants untrusted code access to repository write permissions and secrets."},
		DefaultConfig:    &RuleDefaultConfig{Level: "error"},
	},
	{
		ID:               domain.FindingWriteAllPermissions.String(),
		ShortDescription: Message{Text: "Workflow or job uses write-all permissions"},
		FullDescription:  &Message{Text: "permissions: write-all grants GITHUB_TOKEN every available scope. Narrow to the minimum required."},
		DefaultConfig:    &RuleDefaultConfig{Level: "error"},
	},
	{
		ID:               domain.FindingScriptInjection.String(),
		ShortDescription: Message{Text: "Attacker-controlled context interpolated into run script"},
		FullDescription:  &Message{Text: "GitHub event context fields such as PR title, branch name, or issue body are attacker-controlled. Interpolating them directly into a run: body enables script injection."},
		DefaultConfig:    &RuleDefaultConfig{Level: "error"},
	},
	{
		ID:               domain.FindingOIDCNpmPublish.String(),
		ShortDescription: Message{Text: "id-token:write permission combined with npm publish"},
		FullDescription:  &Message{Text: "A job with id-token:write can mint a short-lived npm token via OIDC federation without any stored secret. Combined with npm publish this is the Mini Shai-Hulud worm self-replication vector."},
		DefaultConfig:    &RuleDefaultConfig{Level: "error"},
	},
	{
		ID:               domain.FindingCachePoisoning.String(),
		ShortDescription: Message{Text: "actions/cache used inside pull_request_target"},
		FullDescription:  &Message{Text: "Fork PRs share the base branch's cache scope. A malicious PR can read previously cached secrets or plant poisoned cache entries that execute on a later privileged workflow run."},
		DefaultConfig:    &RuleDefaultConfig{Level: "error"},
	},
}

// ActionsToSARIF converts an ActionsScanResult to a SARIF 2.1.0 Log.
// toolVersion is the aegis-cli version string stamped at build time.
// baseDir is stripped from finding file paths to produce repo-relative URIs
// that GitHub Code Scanning can resolve (pass the project root; "" = no strip).
func ActionsToSARIF(result usecase.ActionsScanResult, toolVersion, baseDir string) Log {
	results := make([]Result, 0, len(result.Findings))
	for _, f := range result.Findings {
		uri := relativeURI(f.File, baseDir)
		r := Result{
			RuleID:  f.Kind.String(),
			Level:   severityToSARIFLevel(f.Severity),
			Message: Message{Text: f.Message},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI:       uri,
						URIBaseID: "%SRCROOT%",
					},
					Region: &Region{StartLine: max(f.Line, 1)},
				},
			}},
		}
		if f.Suppressed {
			r.Suppressions = []Suppression{{
				Kind:          "external",
				Justification: f.SuppressBy,
			}}
		}
		results = append(results, r)
	}

	return Log{
		Version: Version210,
		Schema:  schema210,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           "aegis-cli",
				Version:        toolVersion,
				InformationURI: "https://github.com/qwexvf/aegis-cli",
				Rules:          actionsRules,
			}},
			Results: results,
		}},
	}
}

// severityToSARIFLevel maps aegis severity to the SARIF level vocabulary.
// SARIF uses: error > warning > note > none.
// relativeURI strips baseDir prefix from path to produce a repo-relative URI.
// Ensures forward slashes and no leading slash so consumers resolve correctly.
func relativeURI(filePath, baseDir string) string {
	if baseDir == "" {
		return filePath
	}
	// Normalise: ensure baseDir ends with /
	if len(baseDir) > 0 && baseDir[len(baseDir)-1] != '/' {
		baseDir += "/"
	}
	rel := strings.TrimPrefix(filePath, baseDir)
	// If no prefix was stripped, return as-is (already relative or different root)
	return rel
}

func severityToSARIFLevel(s domain.Severity) string {
	switch s {
	case domain.SevCritical, domain.SevHigh:
		return "error"
	case domain.SevMedium:
		return "warning"
	case domain.SevLow:
		return "note"
	}
	return "warning"
}
