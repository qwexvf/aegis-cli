package cli

import (
	"fmt"
	"os"

	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// explainCommand wires `aegis explain <pkg-spec>`. Looks up the dep
// in the saved aegis.lock first; falls back to a fresh fetch + scan
// when not present. Prints capability descriptions, flag breakdown,
// and (when fresh-scanned) per-capture evidence.
//
// Spec format matches `aegis analyze`: [ecosystem/]name@version.
//
// Exit codes:
//
//	0   safe / review verdict
//	1   prompt / block verdict (presenter already explained why)
//	2   couldn't reach a verdict (fetch error, malformed spec, etc.)
func explainCommand(uc *usecase.Explain, presenter *presentercli.ExplainPresenter) *cobra.Command {
	var (
		jsonOut       bool
		snapshotOnly  bool
	)
	cmd := &cobra.Command{
		Use:   "explain <pkg-spec>",
		Short: "Show why a dep was flagged — capability descriptions + risk breakdown + evidence",
		Long: `explain looks up the dep in the saved aegis.lock first (no network).
If not found, falls back to a fresh fetch + AST scan.

Each capability is shown with a one-line human description; flags
include the suppression reason when allowlisted; evidence (file:line
snippets) is shown when the scan was fresh.

Examples:
  aegis explain lodash@4.17.21
  aegis explain @solana/web3.js@1.95.4
  aegis explain --snapshot-only ua-parser-js@0.7.29   # error if not in lock`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			eco, name, version, err := parsePkgSpec(args[0])
			if err != nil {
				return err
			}
			presenter.SetJSONMode(jsonOut)

			result, runErr := uc.Run(cmd.Context(), usecase.ExplainRequest{
				ProjectDir:     cwd,
				Ecosystem:      eco,
				Name:           name,
				Version:        version,
				AllowFreshScan: !snapshotOnly,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if runErr != nil {
				return &exitCodeError{code: 2, err: runErr, silent: true}
			}
			// Match analyze's exit-code contract: prompt/block → 1.
			if result.Verdict.String() == "prompt" || result.Verdict.String() == "block" {
				return &exitCodeError{
					code:   1,
					err:    fmt.Errorf("%s@%s: %s", name, version, result.Verdict),
					silent: true,
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit machine-readable JSON to stdout")
	cmd.Flags().BoolVar(&snapshotOnly, "snapshot-only", false,
		"only consult the saved aegis.lock; never fetch + rescan")
	return cmd
}
