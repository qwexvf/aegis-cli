package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis-cli/internal/infra/sarif"
	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// ciCommand wires `aegis ci` — the turnkey CI audit. Orchestrates
// snapshot save → enrich → score → threshold filter → exit code.
//
// Exit codes:
//
//	0   passed (no findings ≥ --fail-on)
//	1   failed (one or more findings ≥ --fail-on)
//	2   couldn't reach a verdict (config error, network failure, etc.)
func ciCommand(uc *usecase.CI, actions *usecase.Actions, presenter *presentercli.CIPresenter) *cobra.Command {
	var (
		failOnStr    string
		jsonOut      bool
		sarifOut     bool
		quiet        bool
		noEnrich     bool
		baselinePath string
		scanActions  bool
	)
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Audit the project for risky deps and exit non-zero on findings (one-stop CI command)",
		Long: `ci runs the full audit pipeline in one shot:

  1. snapshot save     write aegis.lock from the live lockfile
  2. snapshot enrich   AST-scan every dep (skip with --no-enrich)
  3. score             apply allowlist + verdict thresholds
  4. exit              0 = passed, 1 = findings, 2 = error

Designed to drop into a CI step:

  - run: aegis ci --fail-on=block
  - run: aegis ci --json | jq '.findings'

The fingerprint cache (~/.aegis/cache/fingerprints) persists across
runs, so a warm CI is fast — only newly-added or version-changed
deps incur AST scan cost.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			failOn, err := parseFailOn(failOnStr)
			if err != nil {
				return err
			}
			presenter.SetJSONMode(jsonOut)
			presenter.SetQuietMode(quiet)

			result, runErr := uc.Run(cmd.Context(), usecase.CIRequest{
				ProjectDir:   cwd,
				FailOn:       failOn,
				Enrich:       !noEnrich,
				BaselinePath: baselinePath,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if runErr != nil {
				return &exitCodeError{code: 2, err: runErr, silent: true}
			}

			// SARIF output: emit package findings, then return.
			if sarifOut {
				log := sarif.CIToSARIF(result, Version)
				b, err := sarif.Marshal(log)
				if err != nil {
					return &exitCodeError{code: 2, err: err, silent: false}
				}
				_, _ = cmd.OutOrStdout().Write(b)
				_, _ = fmt.Fprintln(cmd.OutOrStdout())
				if !result.Passed {
					active := 0
					for _, f := range result.Findings {
						if f.Verdict >= failOn {
							active++
						}
					}
					return &exitCodeError{code: 1, err: fmt.Errorf("ci: %d finding(s) ≥ %s", active, failOn), silent: true}
				}
				return nil
			}

			// Actions scan integration: run after package scan.
			actionsPass := true
			if scanActions {
				ignore, _ := allowlist.LoadActionsIgnore(cwd)
				aResult, aErr := actions.Scan(cmd.Context(), usecase.ActionsScanRequest{
					ProjectDir: cwd,
					FailOn:     domain.SevHigh,
					Ignore:     ignore,
				})
				if aErr != nil {
					return &exitCodeError{code: 2, err: fmt.Errorf("actions scan: %w", aErr), silent: false}
				}
				actionsPass = aResult.Passed
				if !jsonOut && !quiet {
					fmt.Fprintf(cmd.OutOrStdout(), "\nactions scan: scanned %d workflow(s)", aResult.Workflows)
					active := 0
					for _, f := range aResult.Findings {
						if !f.Suppressed {
							active++
						}
					}
					if active > 0 {
						fmt.Fprintf(cmd.OutOrStdout(), ", %d finding(s)\n", active)
					} else {
						fmt.Fprintln(cmd.OutOrStdout(), ", no findings")
					}
				}
			}

			if !result.Passed || !actionsPass {
				active := len(result.Findings)
				return &exitCodeError{
					code:   1,
					err:    fmt.Errorf("ci: %d finding(s) ≥ %s", active, failOn),
					silent: true,
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOnStr, "fail-on", "block",
		"verdict threshold to fail on: safe|review|prompt|block")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit a machine-readable JSON object to stdout (suppresses human output)")
	cmd.Flags().BoolVar(&quiet, "quiet", false,
		"print only the summary line (no per-finding detail)")
	cmd.Flags().BoolVar(&noEnrich, "no-enrich", false,
		"skip the AST scan; score only on existing fingerprints (faster but thinner)")
	cmd.Flags().BoolVar(&sarifOut, "sarif", false,
		"emit package findings as SARIF 2.1.0 (for GitHub Code Scanning)")
	cmd.Flags().BoolVar(&scanActions, "scan-actions", false,
		"also scan .github/workflows/ and fail if Actions findings ≥ high")
	cmd.Flags().StringVar(&baselinePath, "baseline", "",
		"path to a saved aegis.lock to diff against (drift mode — catches "+
			"version-changed deps that grew new capabilities; doesn't touch your aegis.lock)")
	return cmd
}

// parseFailOn maps the user's --fail-on string to a VerdictKind.
// Case-insensitive; leading/trailing whitespace tolerated.
func parseFailOn(s string) (domain.VerdictKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "safe":
		return domain.VerdictSafe, nil
	case "review":
		return domain.VerdictReview, nil
	case "prompt":
		return domain.VerdictPrompt, nil
	case "block":
		return domain.VerdictBlock, nil
	}
	return 0, fmt.Errorf("invalid --fail-on %q: want one of safe|review|prompt|block", s)
}
