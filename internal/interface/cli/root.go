// Package cli builds the Cobra command tree for `aegis`. It depends
// on usecase + infra ports — no domain logic lives here. Each command
// is a thin shell that translates argv → port calls and exits.
package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
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
	Analyze  *usecase.Analyze
	Cache    *diskcache.Cache
	Audit    *ndjsonaudit.Writer
	Managers []pmwrapper.PackageManager

	// AnalyzePresenter is held by Deps so the analyze command can flip
	// JSON mode at run time before invoking the use case. When nil,
	// the analyze subcommand is not registered.
	AnalyzePresenter *presentercli.AnalyzePresenter

	// CI + CIPresenter wire `aegis ci`. CIPresenter is held by Deps
	// so the command can flip --json / --quiet modes after argv
	// parses. When either is nil, the ci subcommand is not registered.
	CI          *usecase.CI
	CIPresenter *presentercli.CIPresenter

	// API is the Aegis API client — used by `aegis doctor` for the
	// reachability check. Optional; when nil, doctor warns but
	// still runs other checks.
	API *aegisapi.Client

	// Recheck + RecheckPresenter wire `aegis recheck`.
	Recheck          *usecase.Recheck
	RecheckPresenter *presentercli.RecheckPresenter

	// Explain + ExplainPresenter wire `aegis explain`.
	Explain          *usecase.Explain
	ExplainPresenter *presentercli.ExplainPresenter

	// Hook wires `aegis hook install` / `uninstall`.
	Hook *usecase.Hook

	// AllowlistLoader is a factory so each invocation of an allowlist
	// subcommand picks up the cwd at run time (matters for project-
	// scoped operations). When nil, the allowlist subcommand is not
	// registered.
	AllowlistLoader    func() *allowlist.Loader
	AllowlistPresenter *presentercli.AllowlistPresenter

	// InvocationID is stamped onto log records and HTTP X-Request-ID
	// headers. Set by the composition root; tests may pass "".
	InvocationID string
}

// NewRoot returns the root cobra.Command with every subcommand wired.
//
// The persistent --verbose flag flips the global slog level to DEBUG
// before any command body runs (via the LogLevel LevelVar installed by
// cmd/aegis/main.configureLogger); without it we stay at WARN. The
// dev-pretty / CI-JSON handler choice is made once in main and doesn't
// need a flag (auto-detected via TTY + CI markers).
func NewRoot(d Deps) *cobra.Command {
	var verbose bool

	root := &cobra.Command{
		Use:           "aegis",
		Short:         "Aegis supply-chain CLI — install gate for npm, bun, yarn, pnpm",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if verbose {
				LogLevel.Set(slog.LevelDebug)
			}
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable debug-level structured logging to stderr")

	root.AddCommand(versionCommand())
	root.AddCommand(cacheCommand(d.Cache))
	root.AddCommand(auditCommand(d.Audit))
	root.AddCommand(adminCommand())
	root.AddCommand(doctorCommand(d.API, d.AllowlistLoader))
	if d.Snapshot != nil {
		root.AddCommand(snapshotCommand(d.Snapshot))
	}
	if d.Analyze != nil && d.AnalyzePresenter != nil {
		root.AddCommand(analyzeCommand(d.Analyze, d.AnalyzePresenter))
	}
	if d.CI != nil && d.CIPresenter != nil {
		root.AddCommand(ciCommand(d.CI, d.CIPresenter))
	}
	if d.Recheck != nil && d.RecheckPresenter != nil {
		root.AddCommand(recheckCommand(d.Recheck, d.RecheckPresenter))
	}
	if d.Explain != nil && d.ExplainPresenter != nil {
		root.AddCommand(explainCommand(d.Explain, d.ExplainPresenter))
	}
	if d.Hook != nil {
		root.AddCommand(hookCommand(d.Hook))
	}
	if d.AllowlistLoader != nil && d.AllowlistPresenter != nil {
		root.AddCommand(allowlistCommand(d.AllowlistLoader, d.AllowlistPresenter))
	}
	for _, m := range d.Managers {
		root.AddCommand(pmCommand(m, d.Gate))
	}
	return root
}

// Execute runs the root command and honors *exitCodeError so commands
// can return distinct exit codes (e.g. analyze: 0 safe / 1 prompt|block
// / 2 fetch-or-analyze-error). Plain errors still exit 1. When the
// returned exitCodeError is silent (presenter already rendered the
// failure), the default "aegis: <err>" line is suppressed.
func Execute(d Deps) {
	root := NewRoot(d)
	err := root.Execute()
	if err == nil {
		return
	}
	var ec *exitCodeError
	if errors.As(err, &ec) {
		if !ec.silent {
			fmt.Fprintln(os.Stderr, "aegis:", err)
		}
		os.Exit(ec.code)
	}
	fmt.Fprintln(os.Stderr, "aegis:", err)
	os.Exit(1)
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
