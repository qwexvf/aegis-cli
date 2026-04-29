package main

import (
	"fmt"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/wrap"
	"github.com/spf13/cobra"
)

const version = "0.1.0-demo"

func main() {
	root := &cobra.Command{
		Use:           "aegis",
		Short:         "Aegis supply-chain CLI — install gate for npm, pip, cargo",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(versionCmd())
	root.AddCommand(npmCmd())

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

func npmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "npm [args...]",
		Short:              "Run npm with aegis supply-chain checks",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return wrap.Npm(args)
		},
	}
	return cmd
}
