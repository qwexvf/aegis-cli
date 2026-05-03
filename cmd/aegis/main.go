// Package main is the composition root for the aegis CLI. It wires
// concrete adapters (infra/) into ports (usecase) and hands off to the
// CLI command tree. This is the ONLY file that constructs adapters —
// every other layer talks to ports, not implementations.
//
// The risk engine (AST scanner + package-source fetcher + fingerprint
// cache) is opt-out via the `nojsscan` build tag. See risk_engine.go
// (default) and risk_engine_off.go (with -tags=nojsscan).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	clii "github.com/qwexvf/aegis/services/cli/internal/interface/cli"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/envprobe"
	"github.com/qwexvf/aegis/services/cli/internal/infra/hookfs"
	"github.com/qwexvf/aegis/services/cli/internal/infra/httpx"
	"github.com/qwexvf/aegis/services/cli/internal/infra/locksnap"
	"github.com/qwexvf/aegis/services/cli/internal/infra/ndjsonaudit"
	"github.com/qwexvf/aegis/services/cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis/services/cli/internal/infra/ttyprompt"
	"github.com/qwexvf/aegis/services/cli/internal/presenter/cli"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// newInvocationID returns a 128-bit hex token used to correlate one
// CLI run's audit entries, HTTP requests, and (later) structured logs.
// Falls back to a fixed sentinel only on the (effectively impossible)
// case that crypto/rand fails — we never block startup on it.
func newInvocationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// configureLogger installs the global slog logger.
//
// Output: TextHandler on dev TTYs (no CI marker, stderr is a terminal),
// JSONHandler elsewhere so log shippers in CI can parse cleanly.
// Level: warn by default, flipped to debug when verbose=true.
//
// Called exactly once at process start. The root command's
// PersistentPreRun later flips the level via clii.LogLevel.Set after
// Cobra parses --verbose; it does NOT call configureLogger again. The
// output writer and the invocation ID are stable for the process lifetime.
func configureLogger(invocationID string, verbose bool) {
	if verbose {
		clii.LogLevel.Set(slog.LevelDebug)
	} else {
		clii.LogLevel.Set(slog.LevelWarn)
	}
	opts := &slog.HandlerOptions{Level: clii.LogLevel}

	var handler slog.Handler
	if shouldPrettyLog() {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	logger := slog.New(handler).With("cli_invocation_id", invocationID)
	slog.SetDefault(logger)
}

// shouldPrettyLog returns true when stderr is a TTY and no CI marker
// is set — i.e. a developer is watching the terminal. CI runs always
// get JSON so log shippers can parse them. CI detection is delegated
// to envprobe.IsCI to keep the marker list in one place.
func shouldPrettyLog() bool {
	if envprobe.IsCI() {
		return false
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func main() {
	// One per-process invocation ID + shared HTTP client. Every
	// outbound call (Aegis API, npm registry, tarball downloads)
	// shares the connection pool and stamps User-Agent + X-Request-ID
	// so server logs can correlate a single CLI run.
	cwd, _ := os.Getwd()
	invocationID := newInvocationID()

	// Global slog setup — JSON to stderr by default; pretty TextHandler
	// when stderr is a TTY and we're not in CI. WARN level out of the
	// box; AEGIS_VERBOSE flips to DEBUG. The root command's --verbose
	// flag re-applies the level after argv parses.
	configureLogger(invocationID, os.Getenv("AEGIS_VERBOSE") != "")

	httpClient := httpx.NewClient(httpx.Config{
		UserAgent: httpx.UserAgent(clii.Version),
		RequestID: invocationID,
	})

	// Adapters.
	resolver := npmregistry.NewResolver(npmregistry.WithHTTPClient(httpClient))
	// AEGIS_API_KEY is the server-issued submit key. The /check
	// endpoint stays unauthenticated; only /reports requires it.
	// Empty key still produces a 401 from the API, which the CLI
	// surfaces verbatim — that's the right UX.
	apiClient := aegisapi.New(
		aegisapi.WithAPIKey(os.Getenv("AEGIS_API_KEY")),
		aegisapi.WithHTTPClient(httpClient),
	)
	cache := diskcache.New()
	audit := ndjsonaudit.New().WithProvenance(clii.Version, invocationID, cwd)
	confirm := ttyprompt.New()
	env := envprobe.New()
	presenter := cli.New()

	// Snapshot adapters.
	store, err := locksnap.NewStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: snapshot store init failed:", err)
		os.Exit(1)
	}
	scanner := locksnap.NewScanner()

	// Use cases.
	gate := usecase.NewInstallGate(resolver, apiClient, cache, audit, confirm, env, presenter)
	snapshot := usecase.NewSnapshot(store, scanner,
		cli.NewEnrichLivePresenter(cli.NewSnapshotPresenter(presenter)),
		clii.Version)
	analyzePresenter := cli.NewAnalyzePresenter(presenter)
	analyze := usecase.NewAnalyze(analyzePresenter)
	ciPresenter := cli.NewCIPresenter(presenter)
	ci := usecase.NewCI(snapshot, ciPresenter)
	recheckPresenter := cli.NewRecheckPresenter(presenter)
	recheck := usecase.NewRecheck(scanner, apiClient, recheckPresenter)
	explainPresenter := cli.NewExplainPresenter(presenter)
	explain := usecase.NewExplain(store, analyze, explainPresenter)
	hookPresenter := cli.NewHookPresenter(presenter)
	hook := usecase.NewHook(hookfs.New(), hookPresenter)

	// Optionally attach the risk engine (AST scanner) + submit
	// pipeline. The implementation is selected at compile time via
	// build tags; see risk_engine.go (default) and risk_engine_off.go.
	attachRiskEngine(snapshot, analyze, apiClient, httpClient)

	// Allowlist: layered builtin + user (~/.aegis/allowlist.yaml) +
	// project (.aegis-allowlist.yaml at cwd). When user/project files
	// fail to parse, we fall back to builtin-only AND surface a
	// loud warning to stderr so the user is prompted to run
	// `aegis allowlist verify`. Never refuse to start.
	// allowlistLoader returns a fresh Loader on each call (cwd may have
	// changed between commands). When the API client has an API key,
	// we attach a ServerLoader so the merged AllowSet picks up the
	// org overlay between user and project layers.
	allowlistLoader := func() *allowlist.Loader {
		cwd, _ := os.Getwd()
		l := allowlist.New(cwd)
		l.WithServer(allowlist.NewServerLoader(l, apiClient))
		return l
	}
	if set, err := allowlistLoader().Load(); err != nil {
		// Surface as both stderr (every user sees this) and a slog
		// warning (correlates via invocation_id). The CLI keeps
		// running with builtin rules.
		fmt.Fprintln(os.Stderr, "aegis: WARNING — allowlist file failed to parse:", err)
		fmt.Fprintln(os.Stderr, "aegis:   falling back to builtin rules only;",
			"run `aegis allowlist verify` to inspect")
		slog.Warn("allowlist parse failed; using builtin rules only", "error", err)
		// Fall back to builtin-only so we keep at least the curated
		// false-positive suppressions. Builtin is verified at
		// compile time so this NewAllowSet cannot fail in practice;
		// if it does, propagate empty.
		if builtin, berr := domain.NewAllowSet(domain.BuiltinAllowRules()); berr == nil {
			snapshot.WithAllowlist(builtin)
			analyze.WithAllowlist(builtin)
			explain.WithAllowlist(builtin)
		}
	} else {
		snapshot.WithAllowlist(set)
		analyze.WithAllowlist(set)
		explain.WithAllowlist(set)
	}

	// PM wrappers — registered per-file with `no<pm>` build tags.
	// See pm_registry.go and pm_<name>.go for the opt-out mechanism.
	// `aegis --help` order matches the file-name ordering of init().
	if len(registeredPMs) == 0 {
		fmt.Fprintln(os.Stderr,
			"aegis: no package managers compiled in — "+
				"build with at least one of npm/bun/yarn/pnpm")
		os.Exit(1)
	}

	clii.Execute(clii.Deps{
		Gate:               gate,
		Snapshot:           snapshot,
		Analyze:            analyze,
		AnalyzePresenter:   analyzePresenter,
		CI:                 ci,
		CIPresenter:        ciPresenter,
		Recheck:            recheck,
		RecheckPresenter:   recheckPresenter,
		Explain:            explain,
		ExplainPresenter:   explainPresenter,
		Hook:               hook,
		API:                apiClient,
		Cache:              cache,
		Audit:              audit,
		Managers:           registeredPMs,
		AllowlistLoader:    allowlistLoader,
		AllowlistPresenter: cli.NewAllowlistPresenter(presenter),
		InvocationID:       invocationID,
	})
}
