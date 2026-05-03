package cli

import (
	"fmt"
	"os"

	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// recheckCommand wires `aegis recheck`. Runs `/check` against every
// dep in the live lockfile (direct only by default) and surfaces
// anything that flipped from allow → block since install — typical
// when an incident lands AFTER the package was installed.
//
// Exit codes:
//
//	0   no findings ≥ block (or ≥ prompt with --fail-on-prompt)
//	1   one or more findings; review and remove/upgrade
//	2   couldn't reach a verdict (scan / config error)
func recheckCommand(uc *usecase.Recheck, presenter *presentercli.RecheckPresenter) *cobra.Command {
	var (
		all          bool
		failOnPrompt bool
		jsonOut      bool
		quiet        bool
	)
	cmd := &cobra.Command{
		Use:   "recheck",
		Short: "Re-run the install gate against the current lockfile",
		Long: `recheck calls /check on every dep in the live lockfile and reports
any that the API now says are blocked (or prompted, with
--fail-on-prompt). Useful after an incident DB update — packages
allowed when installed may now be flagged.

By default only DIRECT deps are rechecked (matches what the user
explicitly asked for at install time). Pass --all to also scan
transitive deps.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			presenter.SetJSONMode(jsonOut)
			presenter.SetQuietMode(quiet)

			result, runErr := uc.Run(cmd.Context(), usecase.RecheckRequest{
				ProjectDir:   cwd,
				IncludeAll:   all,
				FailOnPrompt: failOnPrompt,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if runErr != nil {
				return &exitCodeError{code: 2, err: runErr, silent: true}
			}
			if !result.Passed {
				return &exitCodeError{
					code:   1,
					err:    fmt.Errorf("recheck: %d finding(s)", len(result.Findings)),
					silent: true,
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false,
		"include transitive deps (default: direct only)")
	cmd.Flags().BoolVar(&failOnPrompt, "fail-on-prompt", false,
		"exit non-zero on prompt verdicts (default: only block fails)")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit machine-readable JSON to stdout")
	cmd.Flags().BoolVar(&quiet, "quiet", false,
		"summary line only (no per-finding detail)")
	return cmd
}
