package cli

import (
	"fmt"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/usecase"
	"github.com/spf13/cobra"
)

// hookCommand wires `aegis hook install` / `uninstall`. Drops a
// pre-commit step that runs `aegis ci --fail-on=block --no-enrich
// --quiet` whenever lockfiles change. Auto-detects the project's
// hook framework: lefthook (preferred) → husky → native git hooks.
func hookCommand(uc *usecase.Hook) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Install / uninstall the aegis pre-commit hook",
	}
	cmd.AddCommand(hookInstallCommand(uc))
	cmd.AddCommand(hookUninstallCommand(uc))
	return cmd
}

func hookInstallCommand(uc *usecase.Hook) *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the aegis pre-commit hook in the current project",
		Long: `install detects the project's hook framework (lefthook → husky → native
git hooks) and writes a managed pre-commit step that runs:

  ` + usecase.HookCommand + `

The step is bracketed by aegis-managed comment markers so re-running
install replaces our entry rather than stacking duplicates, and
uninstall removes only our entry — the rest of your hook config is
left untouched.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if err := uc.Install(cwd); err != nil {
				return &exitCodeError{code: 1, err: fmt.Errorf("hook install: %w", err), silent: true}
			}
			return nil
		},
	}
}

func hookUninstallCommand(uc *usecase.Hook) *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the aegis pre-commit hook from the current project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if err := uc.Uninstall(cwd); err != nil {
				return &exitCodeError{code: 1, err: fmt.Errorf("hook uninstall: %w", err), silent: true}
			}
			return nil
		},
	}
}
