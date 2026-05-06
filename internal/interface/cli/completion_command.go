package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// completionCommand registers `aegis completion {bash|zsh|fish|powershell}`
// so users can install shell completions. Cobra generates the script;
// this command just exposes it.
func completionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for aegis.

Bash:
  source <(aegis completion bash)

  # persistent (Linux):
  aegis completion bash > /etc/bash_completion.d/aegis

Zsh:
  # persistent:
  aegis completion zsh > "${fpath[1]}/_aegis"
  # then restart your shell

Fish:
  aegis completion fish | source
  # persistent:
  aegis completion fish > ~/.config/fish/completions/aegis.fish

PowerShell:
  aegis completion powershell | Out-String | Invoke-Expression`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		GroupID:               groupMaintain,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(out, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(out)
			case "fish":
				return cmd.Root().GenFishCompletion(out, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(out)
			default:
				return fmt.Errorf("unknown shell: %s", args[0])
			}
		},
	}
	return cmd
}
