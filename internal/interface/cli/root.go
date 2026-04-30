// Package cli builds the Cobra command tree for `aegis`. It depends
// on usecase + infra ports — no domain logic lives here. Each command
// is a thin shell that translates argv → port calls and exits.
package cli

import (
	"fmt"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/logx"
	"github.com/qwexvf/aegis/services/cli/internal/infra/ndjsonaudit"
	"github.com/qwexvf/aegis/services/cli/internal/infra/pmwrapper"
	presentercli "github.com/qwexvf/aegis/services/cli/internal/presenter/cli"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
	"github.com/spf13/cobra"
)

// Version is stamped at build time by the composition root.
var Version = "0.1.0-demo"

// Deps bundles the wired ports the command tree needs. Constructed by
// cmd/aegis/main; tests can substitute fakes.
type Deps struct {
	Gate     *usecase.InstallGate
	Snapshot *usecase.Snapshot
	Cache    *diskcache.Cache
	Audit    *ndjsonaudit.Writer
	Managers []pmwrapper.PackageManager

	// AllowlistLoader is a factory so each invocation of an allowlist
	// subcommand picks up the cwd at run time (matters for project-
	// scoped operations). When nil, the allowlist subcommand is not
	// registered.
	AllowlistLoader    func() *allowlist.Loader
	AllowlistPresenter *presentercli.AllowlistPresenter

	// InvocationID is stamped onto slog records and HTTP X-Request-ID
	// headers. Set by the composition root; tests may pass "".
	InvocationID string
}

// NewRoot returns the root cobra.Command with every subcommand wired.
//
// Persistent flags --verbose / --log-format apply to every subcommand
// and reconfigure the slog default. The composition root installs an
// initial logger at WARN; --verbose flips it to DEBUG before any
// command body runs.
func NewRoot(d Deps) *cobra.Command {
	var verbose bool
	var logFormat string

	root := &cobra.Command{
		Use:           "aegis",
		Short:         "Aegis supply-chain CLI — install gate for npm, bun, yarn, pnpm",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			format := logx.FormatAuto
			switch logFormat {
			case "text":
				format = logx.FormatText
			case "json":
				format = logx.FormatJSON
			}
			logx.SetDefault(logx.New(logx.Config{
				Verbose:      verbose,
				Format:       format,
				InvocationID: d.InvocationID,
			}))
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable debug-level structured logging to stderr")
	root.PersistentFlags().StringVar(&logFormat, "log-format", "auto",
		"log format: auto|text|json")

	root.AddCommand(versionCommand())
	root.AddCommand(cacheCommand(d.Cache))
	root.AddCommand(auditCommand(d.Audit))
	root.AddCommand(adminCommand())
	if d.Snapshot != nil {
		root.AddCommand(snapshotCommand(d.Snapshot))
	}
	if d.AllowlistLoader != nil && d.AllowlistPresenter != nil {
		root.AddCommand(allowlistCommand(d.AllowlistLoader, d.AllowlistPresenter))
	}
	for _, m := range d.Managers {
		root.AddCommand(pmCommand(m, d.Gate))
	}
	return root
}

// Execute runs the root command and exits on error. Used by main.
func Execute(d Deps) {
	root := NewRoot(d)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis:", err)
		os.Exit(1)
	}
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print aegis version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aegis %s\n", Version)
		},
	}
}
