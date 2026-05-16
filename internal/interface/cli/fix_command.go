package cli

import (
	"fmt"
	"os"

	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// fixCommand wires `aegis fix` — load the saved snapshot, compute the
// minimal upgrade plan that clears every CVE with a known FixedIn, and
// print the result.
//
// Three output modes:
//
//	(default)         human-readable plan with per-dep advisory list
//	--json            machine-readable JSON on stdout
//	--script          only the upgrade commands, one per line — pipe to sh
//
// Exit codes:
//
//	0   plan empty (no advisories) OR plan emitted
//	1   plan has unresolved advisories (no FixedIn) AND --strict
//	2   load / build failure
func fixCommand(uc *usecase.Fix, presenter *presentercli.FixPresenter) *cobra.Command {
	var (
		jsonOut    bool
		scriptOut  bool
		strict     bool
		projectDir string
	)
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Compute the minimal upgrade plan that clears every CVE in the snapshot",
		Long: `fix loads the saved aegis.lock, groups advisories by dep, and picks the
highest FixedIn version across each dep's advisories — the smallest single
upgrade that clears every resolvable CVE.

Run after 'aegis snapshot enrich' so each dep carries its advisories.

Output modes:

  aegis fix              human-readable plan
  aegis fix --json       JSON on stdout (tooling integration)
  aegis fix --script     only upgrade commands, suitable for: aegis fix --script | sh

The plan is informational — fix never writes to your lockfile or runs the
upgrade commands directly. Review and apply selectively.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectDir == "" {
				cwd, err := os.Getwd()
				if err != nil {
					return err
				}
				projectDir = cwd
			}
			presenter.SetJSONMode(jsonOut)
			presenter.SetScriptMode(scriptOut)

			result, runErr := uc.Run(usecase.FixRequest{ProjectDir: projectDir})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if runErr != nil {
				return &exitCodeError{code: 2, err: runErr, silent: true}
			}

			if strict {
				for _, item := range result.Plan.Items {
					if len(item.UnresolvedAdvisories) > 0 {
						return &exitCodeError{
							code:   1,
							err:    fmt.Errorf("fix: unresolved advisories present (--strict)"),
							silent: true,
						}
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit machine-readable JSON on stdout (suppresses human output)")
	cmd.Flags().BoolVar(&scriptOut, "script", false,
		"emit only upgrade commands, one per line — pipe to sh to apply")
	cmd.Flags().BoolVar(&strict, "strict", false,
		"exit 1 when any advisory has no upstream fix (forces manual review)")
	cmd.Flags().StringVar(&projectDir, "dir", "",
		"project directory to scan (default: cwd)")
	return cmd
}
