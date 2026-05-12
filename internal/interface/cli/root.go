// Package cli builds the Cobra command tree for `aegis`. It depends
// on usecase + infra ports — no domain logic lives here. Each command
// is a thin shell that translates argv → port calls and exits.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/qwexvf/aegis-cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis-cli/internal/infra/config"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis-cli/internal/infra/ndjsonaudit"
	"github.com/qwexvf/aegis-cli/internal/infra/pmwrapper"
	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// contextKeyConfig is the unexported context key for the loaded Config.
type contextKeyConfig struct{}

// configFromContext retrieves the Config stored by PersistentPreRunE.
// Returns a zero Config if not set (e.g. in tests).
func configFromContext(ctx context.Context) config.Config {
	if v := ctx.Value(contextKeyConfig{}); v != nil {
		return v.(config.Config)
	}
	return config.Config{}
}

// Command groups for `aegis --help`. Order here is the order they
// render in.
const (
	groupGate      = "gate"
	groupInspect   = "inspect"
	groupConfigure = "configure"
	groupMaintain  = "maintain"
)

// Version, Commit, and Date are stamped at build time via -ldflags=-X.
// GoReleaser sets all three on tagged releases; local `go build` falls
// back to these defaults so the binary still runs and reports something.
var (
	Version = "0.1.0-demo"
	Commit  = "none"
	Date    = "unknown"
)

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

	// Sbom wires `aegis sbom`. When nil, the subcommand is not
	// registered.
	Sbom *usecase.Sbom

	// Actions wires `aegis actions scan` — GitHub Actions workflow
	// scanner. Optional; nil disables the subcommand.
	Actions *usecase.Actions

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
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if verbose {
				LogLevel.Set(slog.LevelDebug)
			}
			// Load aegis.yml from cwd and store in context so sub-commands
			// can apply config defaults for flags not explicitly set.
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			cfg, err := config.Load(cwd)
			if err != nil {
				return fmt.Errorf("aegis.yml: %w", err)
			}
			cmd.SetContext(context.WithValue(cmd.Context(), contextKeyConfig{}, cfg))
			return nil
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable debug-level structured logging to stderr")

	root.AddGroup(
		&cobra.Group{ID: groupGate, Title: "Install gate:"},
		&cobra.Group{ID: groupInspect, Title: "Inspect:"},
		&cobra.Group{ID: groupConfigure, Title: "Configure:"},
		&cobra.Group{ID: groupMaintain, Title: "Maintain:"},
	)

	add := func(c *cobra.Command, group string) {
		c.GroupID = group
		root.AddCommand(c)
	}

	add(versionCommand(), groupMaintain)
	add(cacheCommand(d.Cache), groupMaintain)
	add(auditCommand(d.Audit), groupInspect)
	add(adminCommand(), groupMaintain)
	add(doctorCommand(d.API, d.AllowlistLoader), groupMaintain)
	if d.Snapshot != nil {
		add(snapshotCommand(d.Snapshot), groupInspect)
	}
	if d.Analyze != nil && d.AnalyzePresenter != nil {
		add(analyzeCommand(d.Analyze, d.AnalyzePresenter), groupInspect)
	}
	if d.CI != nil && d.CIPresenter != nil {
		add(ciCommand(d.CI, d.Actions, d.CIPresenter), groupGate)
	}
	if d.Recheck != nil && d.RecheckPresenter != nil {
		add(recheckCommand(d.Recheck, d.RecheckPresenter), groupGate)
	}
	if d.Explain != nil && d.ExplainPresenter != nil {
		add(explainCommand(d.Explain, d.ExplainPresenter), groupInspect)
	}
	if d.Hook != nil {
		add(hookCommand(d.Hook), groupConfigure)
	}
	if d.Sbom != nil {
		add(sbomCommand(d.Sbom), groupInspect)
	}
	if d.Actions != nil {
		add(actionsCommand(d.Actions), groupInspect)
	}
	if d.AllowlistLoader != nil && d.AllowlistPresenter != nil {
		add(allowlistCommand(d.AllowlistLoader, d.AllowlistPresenter), groupConfigure)
	}
	for _, m := range d.Managers {
		add(pmCommand(m, d.Gate), groupGate)
	}

	root.AddCommand(completionCommand())

	return root
}

// Execute runs the root command and honors *exitCodeError so commands
// can return distinct exit codes (e.g. analyze: 0 safe / 1 prompt|block
// / 2 fetch-or-analyze-error). Plain errors still exit 1. When the
// returned exitCodeError is silent (presenter already rendered the
// failure), the default "aegis: <err>" line is suppressed.
func Execute(d Deps) {
	// Signal-aware context: SIGINT/SIGTERM cancels long-running ops
	// (snapshot enrich, ci, analyze) instead of dropping mid-flight
	// HTTP requests. A second signal exits 130 without waiting for
	// graceful shutdown — standard Unix convention.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := NewRoot(d)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		os.Exit(130)
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

// NewDocsRoot returns a *cobra.Command tree populated with every
// subcommand for offline doc generation (man pages, markdown). The
// command bodies close over zero-value usecase / presenter pointers
// — never invoke .Execute() on the returned tree, only walk it via
// cobra/doc generators which only inspect Use / Short / Long / Flags.
func NewDocsRoot() *cobra.Command {
	d := Deps{
		Snapshot:           &usecase.Snapshot{},
		Analyze:            &usecase.Analyze{},
		CI:                 &usecase.CI{},
		Recheck:            &usecase.Recheck{},
		Explain:            &usecase.Explain{},
		Hook:               &usecase.Hook{},
		Sbom:               &usecase.Sbom{},
		Actions:            &usecase.Actions{},
		AnalyzePresenter:   &presentercli.AnalyzePresenter{},
		CIPresenter:        &presentercli.CIPresenter{},
		RecheckPresenter:   &presentercli.RecheckPresenter{},
		ExplainPresenter:   &presentercli.ExplainPresenter{},
		AllowlistPresenter: &presentercli.AllowlistPresenter{},
		AllowlistLoader:    func() *allowlist.Loader { return nil },
	}
	return NewRoot(d)
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print aegis version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "aegis %s (commit %s, built %s)\n", Version, Commit, Date)
			return err
		},
	}
}
