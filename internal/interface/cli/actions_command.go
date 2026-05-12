package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// actionsCommand wires `aegis actions` and its subcommands. Today only
// `scan` exists; future subcommands (audit remote repos, allowlist
// management for known-suspicious actions) hang off the same parent.
//
// Exit codes:
//
//	0   passed (no findings ≥ --fail-on)
//	1   failed (one or more findings ≥ --fail-on)
//	2   couldn't reach a verdict (workflow dir unreadable, YAML
//	    invalid, etc.)
func actionsCommand(uc *usecase.Actions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "actions",
		Short: "Scan GitHub Actions workflows for supply-chain risks",
		Long: `actions scans .github/workflows/*.yml for known risky patterns:

  - unpinned action refs (tag/branch instead of commit SHA)
  - suspicious run-script bodies (curl|sh, base64 decode, raw IPs)
  - pull_request_target jobs that check out PR code
  - permissions: write-all
  - attacker-controlled GitHub-context interpolation in run scripts

This is heuristic, not exhaustive — designed to catch the patterns
behind real-world incidents (tj-actions/changed-files 2025-03 etc).`,
	}
	cmd.AddCommand(actionsScanCommand(uc))
	return cmd
}

func actionsScanCommand(uc *usecase.Actions) *cobra.Command {
	var (
		failOnStr  string
		jsonOut    bool
		projectDir string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan .github/workflows/ in the current project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if projectDir == "" {
				cwd, err := os.Getwd()
				if err != nil {
					return err
				}
				projectDir = cwd
			}
			failOn, err := parseSeverity(failOnStr)
			if err != nil {
				return err
			}
			ignore, err := allowlist.LoadActionsIgnore(projectDir)
			if err != nil {
				return fmt.Errorf("actions allowlist: %w", err)
			}
			result, err := uc.Scan(usecase.ActionsScanRequest{
				ProjectDir: projectDir,
				FailOn:     failOn,
				Ignore:     ignore,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if err != nil {
				return &exitCodeError{code: 2, err: err, silent: false}
			}
			renderActionsResult(cmd.OutOrStdout(), result, jsonOut)
			if !result.Passed {
				active := 0
				for _, f := range result.Findings {
					if !f.Suppressed {
						active++
					}
				}
				return &exitCodeError{
					code:   1,
					err:    fmt.Errorf("actions: %d finding(s) ≥ %s", active, failOn),
					silent: true,
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOnStr, "fail-on", "high",
		"min severity to fail on: low|medium|high|critical")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit findings as JSON")
	cmd.Flags().StringVar(&projectDir, "dir", "",
		"project root (default: cwd)")
	return cmd
}

func parseSeverity(s string) (domain.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return domain.SevLow, nil
	case "medium":
		return domain.SevMedium, nil
	case "high":
		return domain.SevHigh, nil
	case "critical":
		return domain.SevCritical, nil
	}
	return "", fmt.Errorf("invalid --fail-on %q: want one of low|medium|high|critical", s)
}

func renderActionsResult(out io.Writer, r usecase.ActionsScanResult, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Workflows int                      `json:"workflows"`
			Findings  []domain.WorkflowFinding `json:"findings"`
			Passed    bool                     `json:"passed"`
		}{r.Workflows, r.Findings, r.Passed})
		return
	}
	fmt.Fprintf(out, "scanned %d workflow(s)\n", r.Workflows)
	if len(r.Findings) == 0 {
		fmt.Fprintln(out, "no findings")
		return
	}
	for _, f := range r.Findings {
		if f.Suppressed {
			fmt.Fprintf(out, "%s:%d  [suppressed] %s: %s", f.File, f.Line, f.Kind, f.Message)
			if f.SuppressBy != "" {
				fmt.Fprintf(out, " (%s)", f.SuppressBy)
			}
			fmt.Fprintln(out)
			continue
		}
		fmt.Fprintf(out, "%s:%d  [%s] %s: %s\n", f.File, f.Line, f.Severity, f.Kind, f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(out, "    evidence: %s\n", f.Evidence)
		}
	}
}
