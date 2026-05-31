package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis-cli/internal/infra/openvex"
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
		failOnStr        string
		jsonOut          bool
		sarifOut         bool
		suggestOut       bool
		quiet            bool
		noEnrich         bool
		baselinePath     string
		scanActions      bool
		actionsFailOnStr string
		denyLicenses     string
		allowLicenses    string
		vexPath          string
		failOnDeprecated bool
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
			// Apply aegis.yml defaults for flags not set on the command line.
			cfg := configFromContext(cmd.Context())
			if !cmd.Flags().Changed("fail-on") && cfg.CI.FailOn != "" {
				failOnStr = cfg.CI.FailOn
			}
			if !cmd.Flags().Changed("scan-actions") && cfg.CI.ScanActions {
				scanActions = true
			}
			if !cmd.Flags().Changed("sarif") && cfg.CI.SARIF {
				sarifOut = true
			}
			if !cmd.Flags().Changed("no-enrich") && cfg.CI.NoEnrich {
				noEnrich = true
			}
			if !cmd.Flags().Changed("actions-fail-on") && cfg.CI.ActionsFailOn != "" {
				actionsFailOnStr = cfg.CI.ActionsFailOn
			}

			failOn, err := parseFailOn(failOnStr)
			if err != nil {
				return &exitCodeError{code: 2, err: err, silent: false}
			}
			if allowLicenses != "" && denyLicenses != "" {
				return &exitCodeError{code: 2, silent: false,
					err: fmt.Errorf("--allow-licenses and --deny-licenses are mutually exclusive; pass only one")}
			}
			if jsonOut && sarifOut {
				return &exitCodeError{code: 2, silent: false,
					err: fmt.Errorf("--json and --sarif are mutually exclusive; pass only one")}
			}
			presenter.SetJSONMode(jsonOut)
			presenter.SetQuietMode(quiet)

			suppressed, vexErr := loadVEX(vexPath)
			if vexErr != nil {
				return &exitCodeError{code: 2, err: vexErr, silent: false}
			}
			result, runErr := uc.Run(cmd.Context(), usecase.CIRequest{
				ProjectDir:           cwd,
				FailOn:               failOn,
				Enrich:               !noEnrich,
				BaselinePath:         baselinePath,
				LicensePolicy:        parseLicensePolicy(allowLicenses, denyLicenses),
				SuppressedAdvisories: suppressed,
				FailOnDeprecated:     failOnDeprecated,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if runErr != nil {
				return &exitCodeError{code: 2, err: runErr, silent: true}
			}

			// Suggest mode: print remediation hints, then return.
			if suggestOut {
				renderSuggestions(cmd.OutOrStdout(), result)
				if !result.Passed {
					return &exitCodeError{code: 1, err: fmt.Errorf("ci: %d finding(s) ≥ %s", len(result.Findings), failOn), silent: true}
				}
				return nil
			}

			// SARIF output: emit package (+ optionally actions) findings, then return.
			if sarifOut {
				var log sarif.Log
				if scanActions {
					// Run actions scan first, then merge both into one SARIF.
					ignore, err := allowlist.LoadActionsIgnore(cwd)
					if err != nil {
						return &exitCodeError{code: 2, err: fmt.Errorf("actions allowlist: %w", err), silent: false}
					}
					actionsFailOn, aErr := parseSeverity(actionsFailOnStr)
					if aErr != nil {
						return aErr
					}
					aResult, aErr := actions.Scan(cmd.Context(), usecase.ActionsScanRequest{
						ProjectDir: cwd,
						FailOn:     actionsFailOn,
						Ignore:     ignore,
					})
					if aErr != nil {
						return &exitCodeError{code: 2, err: fmt.Errorf("actions scan: %w", aErr), silent: false}
					}
					log = sarif.MergedToSARIF(result, aResult, Version, cwd)
					if !result.Passed || !aResult.Passed {
						b, _ := sarif.Marshal(log)
						_, _ = cmd.OutOrStdout().Write(b)
						_, _ = fmt.Fprintln(cmd.OutOrStdout())
						return &exitCodeError{code: 1, err: fmt.Errorf("ci: findings ≥ threshold"), silent: true}
					}
				} else {
					log = sarif.CIToSARIF(result, Version)
				}
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
				ignore, err := allowlist.LoadActionsIgnore(cwd)
				if err != nil {
					return &exitCodeError{code: 2, err: fmt.Errorf("actions allowlist: %w", err), silent: false}
				}
				actionsFailOn, aFailOnErr := parseSeverity(actionsFailOnStr)
				if aFailOnErr != nil {
					return aFailOnErr
				}
				aResult, aErr := actions.Scan(cmd.Context(), usecase.ActionsScanRequest{
					ProjectDir: cwd,
					FailOn:     actionsFailOn,
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
		"also scan .github/workflows/ and fail if Actions findings ≥ --actions-fail-on")
	cmd.Flags().StringVar(&actionsFailOnStr, "actions-fail-on", "high",
		"min severity for --scan-actions: low|medium|high|critical")
	cmd.Flags().BoolVar(&suggestOut, "suggest", false,
		"print remediation commands for each blocked dep (upgrade hints)")
	cmd.Flags().StringVar(&baselinePath, "baseline", "",
		"path to a saved aegis.lock to diff against (drift mode — catches "+
			"version-changed deps that grew new capabilities; doesn't touch your aegis.lock)")
	cmd.Flags().StringVar(&denyLicenses, "deny-licenses", "",
		"comma-separated SPDX license IDs to reject (e.g. GPL-3.0,AGPL-3.0); "+
			"mutually exclusive with --allow-licenses")
	cmd.Flags().StringVar(&allowLicenses, "allow-licenses", "",
		"comma-separated SPDX license IDs to permit; any other license (or unknown) is blocked; "+
			"mutually exclusive with --deny-licenses")
	cmd.Flags().StringVar(&vexPath, "vex", "",
		"path to an OpenVEX document (.vex JSON); advisories with status 'not_affected' are suppressed")
	cmd.Flags().BoolVar(&failOnDeprecated, "fail-on-deprecated", false,
		"treat deprecated packages as a finding at Review level")
	return cmd
}

// loadVEX parses an OpenVEX file and returns the suppressed advisory ID set.
// Returns (nil, nil) when path is empty (no-op). Uses the openvex package
// to parse; any file error or JSON error returns (nil, err).
func loadVEX(path string) (map[string]struct{}, error) {
	if path == "" {
		return nil, nil
	}
	doc, err := openvex.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--vex: %w", err)
	}
	return openvex.SuppressedAdvisories(doc), nil
}

// parseLicensePolicy builds a domain.LicensePolicy from the raw
// --allow-licenses / --deny-licenses flag strings (comma-separated
// SPDX IDs). Empty strings produce an empty (no-op) policy.
func parseLicensePolicy(allow, deny string) domain.LicensePolicy {
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	return domain.LicensePolicy{Allow: split(allow), Deny: split(deny)}
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
