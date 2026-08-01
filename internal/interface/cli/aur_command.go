package cli

import (
	"fmt"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/aursource"
	"github.com/qwexvf/aegis-cli/internal/infra/pmwrapper"
	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// aurCommand wires `aegis aur scan <path|pkgname>` — scan a PKGBUILD
// (local file/dir or a named AUR package) for malware-delivery patterns
// without installing anything.
func aurCommand(fetcher usecase.AURFetcher, pres *presentercli.AURPresenter) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "aur",
		Short:   "Scan Arch User Repository (AUR) packages for malware",
		GroupID: groupInspect,
	}

	scan := &cobra.Command{
		Use:   "scan <pkgname | ./PKGBUILD | ./dir>",
		Short: "Statically scan a PKGBUILD for malicious build steps",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			var pkg domain.AURPackage
			var err error
			if _, statErr := os.Stat(target); statErr == nil {
				pkg, err = aursource.ReadLocal(target)
			} else if fetcher != nil {
				pkg, err = fetcher.Fetch(cmd.Context(), target)
			} else {
				return fmt.Errorf("%q is not a local path and AUR fetch is unavailable", target)
			}
			if err != nil {
				return err
			}
			res := domain.ScanPKGBUILD(pkg)
			pres.OnAURResult(res)
			if res.Verdict == domain.AURBlock {
				return &exitCodeError{code: 1, err: fmt.Errorf("aur scan: blocked"), silent: true}
			}
			return nil
		},
	}
	cmd.AddCommand(scan)
	return cmd
}

// aurHelperCommand wraps one Arch helper (paru/yay/pacman): on an
// install command it runs the AUR gate first, then delegates to the
// real tool unless something was blocked.
func aurHelperCommand(helper *pmwrapper.AURHelper, gate *usecase.AURGate) *cobra.Command {
	name := helper.Name()
	return &cobra.Command{
		Use:                fmt.Sprintf("%s [args...]", name),
		Short:              fmt.Sprintf("Run %s with aegis PKGBUILD checks", name),
		GroupID:            groupGate,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if helper.IsInstallCommand(args) {
				res, err := gate.Run(cmd.Context(), usecase.AURRequest{
					HelperName: name,
					Targets:    helper.ParseTargets(args),
				})
				if err != nil {
					return err
				}
				if res.AnyBlocked {
					return &exitCodeError{
						code:   1,
						err:    fmt.Errorf("%s: install blocked by aegis gate", name),
						silent: true,
					}
				}
			}
			return helper.Exec(cmd.Context(), args)
		},
	}
}
