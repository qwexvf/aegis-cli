package cli

import (
	"os"

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
	var all bool
	c := &cobra.Command{
		Use:   "show",
		Short: "Print the saved snapshot. By default only direct deps are shown.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			return uc.Show(cwd, !all)
		},
	}
	c.Flags().BoolVar(&all, "all", false, "show transitive deps as well")
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
