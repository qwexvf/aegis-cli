package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/qwexvf/aegis-cli/internal/infra/pmwrapper"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// pmCommand wires one package manager to the install gate. argv:
//   - if it's an install command → run gate, exit 1 if anything blocked,
//     else delegate to the real PM
//   - else → delegate straight away (passthrough)
func pmCommand(pm pmwrapper.PackageManager, gate *usecase.InstallGate) *cobra.Command {
	name := pm.Name()
	return &cobra.Command{
		Use:                fmt.Sprintf("%s [args...]", name),
		Short:              fmt.Sprintf("Run %s with aegis supply-chain checks", name),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pm.IsInstallCommand(args) {
				toks := pm.ParseInstallArgs(args)
				specs := pmwrapper.SpecsToDomain(pm.Ecosystem(), toks)

				res, err := gate.Run(context.Background(), usecase.Request{
					PMName:      pm.Name(),
					InstallVerb: pm.InstallVerb(),
					Specs:       specs,
				})
				if err != nil {
					return err
				}
				if res.AnyBlocked {
					os.Exit(1)
				}
			}
			return pm.Exec(args)
		},
	}
}
