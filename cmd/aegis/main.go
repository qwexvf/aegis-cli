package main

import (
	"fmt"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/pm"
	"github.com/spf13/cobra"
)

const version = "0.1.0-demo"

func main() {
	root := &cobra.Command{
		Use:           "aegis",
		Short:         "Aegis supply-chain CLI — install gate for npm, bun, yarn",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(versionCmd())

	managers := []pm.PackageManager{pm.NewNpm(), pm.NewBun(), pm.NewYarn(), pm.NewPnpm()}
	for _, m := range managers {
		root.AddCommand(pmCmd(m))
	}

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis:", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print aegis version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aegis %s\n", version)
		},
	}
}

func pmCmd(m pm.PackageManager) *cobra.Command {
	name := m.Name()
	return &cobra.Command{
		Use:                fmt.Sprintf("%s [args...]", name),
		Short:              fmt.Sprintf("Run %s with aegis supply-chain checks", name),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return pm.NewRunner(m).Run(args)
		},
	}
}
