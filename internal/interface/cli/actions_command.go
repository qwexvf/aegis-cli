package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis-cli/internal/infra/sarif"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// ansiEscapePattern matches ANSI terminal escape sequences.
// Stripped from Evidence output to prevent terminal injection via
// crafted workflow file content.
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
}

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
		sarifOut   bool
		projectDir string
		repo       string
		token      string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan .github/workflows/ in the current project or a remote GitHub repo",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Apply aegis.yml defaults for flags not set on the command line.
			cfg := configFromContext(cmd.Context())
			if !cmd.Flags().Changed("min-severity") && !cmd.Flags().Changed("fail-on") && cfg.Actions.FailOn != "" {
				failOnStr = cfg.Actions.FailOn
			}
			if !cmd.Flags().Changed("repo") && cfg.Actions.Repo != "" {
				repo = cfg.Actions.Repo
			}

			if projectDir == "" && repo == "" {
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
			var ignore domain.ActionsIgnoreSet
			if projectDir != "" {
				ignore, err = allowlist.LoadActionsIgnore(projectDir)
				if err != nil {
					return fmt.Errorf("actions allowlist: %w", err)
				}
			}
			// Fall back to $GITHUB_TOKEN when --token is not set.
			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}
			result, err := uc.Scan(cmd.Context(), usecase.ActionsScanRequest{
				ProjectDir: projectDir,
				Repo:       repo,
				Token:      token,
				FailOn:     failOn,
				Ignore:     ignore,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if err != nil {
				return &exitCodeError{code: 2, err: err, silent: false}
			}
			renderActionsResult(cmd.OutOrStdout(), result, jsonOut, sarifOut, projectDir)
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
	cmd.Flags().StringVar(&failOnStr, "min-severity", "high",
		"minimum severity to fail on: low|medium|high|critical")
	// --fail-on is the legacy name; kept for backward compatibility.
	cmd.Flags().StringVar(&failOnStr, "fail-on", "high", "")
	_ = cmd.Flags().MarkDeprecated("fail-on", "use --min-severity instead")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit findings as JSON")
	cmd.Flags().BoolVar(&sarifOut, "sarif", false,
		"emit findings as SARIF 2.1.0 (for GitHub Code Scanning / VS Code)")
	cmd.Flags().StringVar(&projectDir, "dir", "",
		"project root (default: cwd); ignored when --repo is set")
	cmd.Flags().StringVar(&repo, "repo", "",
		"remote GitHub repository to scan (owner/repo); fetches workflows via GitHub API")
	cmd.Flags().StringVar(&token, "token", "",
		"GitHub personal access token for --repo; prefer $GITHUB_TOKEN env var (CLI args are visible in process list)")
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
	return "", fmt.Errorf("invalid --min-severity %q: want one of low|medium|high|critical", s)
}

func renderActionsResult(out io.Writer, r usecase.ActionsScanResult, asJSON, asSARIF bool, baseDir string) {
	if asSARIF {
		log := sarif.ActionsToSARIF(r, Version, baseDir)
		b, err := sarif.Marshal(log)
		if err != nil {
			fmt.Fprintf(out, `{"error":%q}`, err.Error())
			return
		}
		_, _ = out.Write(b)
		_, _ = fmt.Fprintln(out)
		return
	}
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
			// Strip ANSI escape sequences before printing Evidence to the terminal.
			// Workflow run: bodies can contain attacker-controlled content that
			// could manipulate terminal state via escape codes.
			fmt.Fprintf(out, "    evidence: %s\n", stripANSI(f.Evidence))
		}
	}
}
