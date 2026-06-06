package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// snapshotCommand wires the snapshot use case to argv. The use case
// itself never reads cwd — we pass it explicitly here so it can be
// driven from tests / scripts.
func snapshotCommand(uc *usecase.Snapshot) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Save / show / diff project dependency snapshots",
	}
	cmd.AddCommand(snapshotSaveCommand(uc))
	cmd.AddCommand(snapshotShowCommand(uc))
	cmd.AddCommand(snapshotDiffCommand(uc))
	cmd.AddCommand(snapshotEnrichCommand(uc))
	cmd.AddCommand(snapshotVerifyCommand(uc))
	cmd.AddCommand(snapshotSubmitCommand(uc))
	cmd.AddCommand(snapshotRescanCommand(uc))
	return cmd
}

func snapshotSubmitCommand(uc *usecase.Snapshot) *cobra.Command {
	return &cobra.Command{
		Use:   "submit",
		Short: "Post analyzed deps as community reports to the Aegis API",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			return uc.Submit(cmd.Context(), cwd)
		},
	}
}

func snapshotEnrichCommand(uc *usecase.Snapshot) *cobra.Command {
	return &cobra.Command{
		Use:   "enrich",
		Short: "Run AST analysis over the saved snapshot to populate fingerprints",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			return uc.Enrich(cmd.Context(), cwd)
		},
	}
}

func snapshotSaveCommand(uc *usecase.Snapshot) *cobra.Command {
	return &cobra.Command{
		Use:   "save",
		Short: "Scan the project's lockfile and write aegis.lock at the project root",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			return uc.Save(cwd)
		},
	}
}

func snapshotShowCommand(uc *usecase.Snapshot) *cobra.Command {
	var all, jsonOut, usedOnly bool
	c := &cobra.Command{
		Use:   "show",
		Short: "Print the saved snapshot. By default only direct deps are shown.",
		// show always reads aegis.lock from cwd; it takes no positional
		// args. Reject stray args instead of silently ignoring them.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			if jsonOut {
				snap, ok, err := uc.Load(cwd)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("no snapshot saved — run 'aegis snapshot save' first")
				}
				if !all || usedOnly {
					filtered := snap.Deps[:0]
					for _, d := range snap.Deps {
						if !all && !d.Direct {
							continue
						}
						if usedOnly && d.Reachability == domain.ReachabilityUnused {
							continue
						}
						filtered = append(filtered, d)
					}
					snap.Deps = filtered
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(snap)
			}
			return uc.Show(cwd, !all, usedOnly)
		},
	}
	c.Flags().BoolVar(&all, "all", false, "show transitive deps as well")
	c.Flags().BoolVar(&usedOnly, "used-only", false, "hide deps marked unreachable from project source")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	return c
}

func snapshotDiffCommand(uc *usecase.Snapshot) *cobra.Command {
	return &cobra.Command{
		Use:   "diff [a.lock] [b.lock]",
		Short: "Diff the saved snapshot against the live lockfile (or two explicit files)",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			a, b := "", ""
			if len(args) == 2 {
				a, b = args[0], args[1]
			}
			return uc.Diff(cwd, a, b)
		},
	}
}

func snapshotVerifyCommand(uc *usecase.Snapshot) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify aegis.lock is loadable and matches the current schema",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			return uc.Verify(cwd)
		},
	}
}

func snapshotRescanCommand(uc *usecase.Snapshot) *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "rescan",
		Short: "Re-query the vulnerability feed for all saved deps and report newly-disclosed advisories",
		Long: `rescan re-queries OSV/GHSA for every dep in aegis.lock regardless of
when it was last enriched. It then diffs against the previously stored
advisories and reports any that are new since the last run.

Exits 1 when new advisories are found — suitable for a daily cron job
that pages on fresh CVEs affecting already-installed deps.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			result, err := uc.Rescan(cmd.Context(), cwd)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			renderRescanResult(cmd, result)
			if result.NewCount > 0 {
				return &exitCodeError{
					code:   1,
					err:    fmt.Errorf("rescan: %d dep(s) have new advisories", result.NewCount),
					silent: true,
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	return c
}

func renderRescanResult(cmd *cobra.Command, r usecase.RescanResult) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "rescan: queried %d dep(s)\n", r.Total)
	if r.NewCount == 0 {
		fmt.Fprintln(w, "rescan: no new advisories found")
		return
	}
	fmt.Fprintf(w, "rescan: %d dep(s) have new advisories\n\n", r.NewCount)
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  %s@%s (%s)\n", f.Name, f.Version, f.Ecosystem)
		for _, a := range f.NewAdvisories {
			line := fmt.Sprintf("    [%s] %s — %s", strings.ToUpper(string(a.Severity)), a.ID, a.Summary)
			if a.URL != "" {
				line += "\n      " + a.URL
			}
			fmt.Fprintln(w, line)
		}
	}
}
