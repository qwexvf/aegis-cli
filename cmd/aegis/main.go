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
	"net/http"
	_ "net/http/pprof" // dev-only profile endpoint, gated on AEGIS_PPROF
	"os"

	clii "github.com/qwexvf/aegis-cli/internal/interface/cli"

	"github.com/qwexvf/aegis-cli/internal/config"
	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis-cli/internal/infra/cratesregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/depsdotdev"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis-cli/internal/infra/envprobe"
	"github.com/qwexvf/aegis-cli/internal/infra/ghsalookup"
	"github.com/qwexvf/aegis-cli/internal/infra/hookfs"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
	"github.com/qwexvf/aegis-cli/internal/infra/licensefetch"
	"github.com/qwexvf/aegis-cli/internal/infra/locksnap"
	"github.com/qwexvf/aegis-cli/internal/infra/ndjsonaudit"
	"github.com/qwexvf/aegis-cli/internal/infra/npmattestations"
	"github.com/qwexvf/aegis-cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/nugetregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/osv"
	"github.com/qwexvf/aegis-cli/internal/infra/pypiregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/rubygemsregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/ttyprompt"
	"github.com/qwexvf/aegis-cli/internal/infra/vulnlookup"
	"github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
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
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	clii.LogLevel.Set(level)
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
	// Optional pprof HTTP endpoint — set AEGIS_PPROF=:6060 to enable.
	// clii.Execute calls os.Exit so file-based cpuprofile flush is
	// awkward; the HTTP endpoint sidesteps that and lets us capture
	// mid-scan with `curl :6060/debug/pprof/profile?seconds=60`.
	if addr := os.Getenv("AEGIS_PPROF"); addr != "" {
		go func() {
			// nolint:gosec // dev-only profile endpoint
			_ = http.ListenAndServe(addr, nil)
		}()
	}

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
	apiClient, err := aegisapi.New(
		aegisapi.WithAPIKey(os.Getenv("AEGIS_API_KEY")),
		aegisapi.WithHTTPClient(httpClient),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis:", err)
		os.Exit(1)
	}
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
	gate := usecase.NewInstallGate(usecase.InstallGateDeps{
		Resolver:  resolver,
		Checker:   apiClient,
		Cache:     cache,
		Audit:     audit,
		Confirm:   confirm,
		Env:       env,
		Presenter: presenter,
	})
	snapshot := usecase.NewSnapshot(store, scanner,
		cli.NewEnrichLivePresenter(cli.NewSnapshotPresenter(presenter)),
		clii.Version)

	// Vulnerability lookup. Providers are configured via
	// ~/.aegis/config.yaml (vuln.sources). When no config file exists
	// the legacy env-var heuristic applies for backwards compatibility:
	//   AEGIS_VULN_SOURCE=osv|aegis|none
	//   AEGIS_NO_VULN_LOOKUP=1  disables lookup entirely
	//
	// When config.yaml defines sources, all enabled providers are
	// queried concurrently and results merged (MultiSource). Env vars
	// still override per-provider credentials (GITHUB_TOKEN, AEGIS_API_KEY,
	// AEGIS_OSV_URL).
	// vulnLookup is captured here so the SBOM use case can reuse the
	// same provider chain (the sbom command's --include-vulns flag
	// goes through this).
	var vulnLookup usecase.VulnLookup
	if os.Getenv("AEGIS_NO_VULN_LOOKUP") == "" {
		cfg, cfgErr := config.Load()
		if cfgErr != nil {
			slog.Warn("config load failed, falling back to env-var heuristic", "err", cfgErr)
		}

		if len(cfg.Vuln.Sources) > 0 {
			// Config-file mode: build a provider per source entry.
			var sources []usecase.VulnLookup
			for _, src := range cfg.Vuln.Sources {
				switch src.Name {
				case "osv":
					opts := []osv.Option{osv.WithHTTPClient(httpClient)}
					if src.URL != "" {
						opts = append(opts, osv.WithBaseURL(src.URL))
					}
					if dir := diskcache.AdvisoryDir(); dir != "" {
						opts = append(opts, osv.WithCacheDir(dir))
					}
					sources = append(sources, osv.New(opts...))
				case "github":
					opts := []ghsalookup.Option{ghsalookup.WithHTTPClient(httpClient)}
					if src.Token != "" {
						opts = append(opts, ghsalookup.WithToken(src.Token))
					}
					sources = append(sources, ghsalookup.New(opts...))
				case "deps.dev":
					opts := []depsdotdev.Option{depsdotdev.WithHTTPClient(httpClient)}
					if src.URL != "" {
						opts = append(opts, depsdotdev.WithBaseURL(src.URL))
					}
					sources = append(sources, depsdotdev.New(opts...))
				case "aegis":
					if src.APIKey != "" || os.Getenv("AEGIS_API_KEY") != "" {
						sources = append(sources, apiClient)
					}
				default:
					slog.Warn("unknown vuln source in config, skipping", "name", src.Name)
				}
			}
			if len(sources) == 1 {
				vulnLookup = sources[0]
			} else if len(sources) > 1 {
				vulnLookup = vulnlookup.MultiSource{Sources: sources}
			}
		} else {
			// Legacy env-var mode for backwards compatibility.
			source := os.Getenv("AEGIS_VULN_SOURCE")
			if source != "none" {
				var osvLookup, aegisLookup usecase.VulnLookup
				if source != "aegis" {
					osvOpts := []osv.Option{osv.WithHTTPClient(httpClient)}
					if u := os.Getenv("AEGIS_OSV_URL"); u != "" {
						osvOpts = append(osvOpts, osv.WithBaseURL(u))
					}
					if dir := diskcache.AdvisoryDir(); dir != "" {
						osvOpts = append(osvOpts, osv.WithCacheDir(dir))
					}
					osvLookup = osv.New(osvOpts...)
				}
				if source != "osv" && os.Getenv("AEGIS_API_KEY") != "" {
					aegisLookup = apiClient
				}
				switch {
				case aegisLookup != nil && osvLookup != nil:
					vulnLookup = vulnlookup.Fallback{
						Primary:   aegisLookup,
						Secondary: osvLookup,
						Logger:    func(format string, args ...any) { slog.Warn(fmt.Sprintf(format, args...)) },
					}
				case aegisLookup != nil:
					vulnLookup = aegisLookup
				case osvLookup != nil:
					vulnLookup = osvLookup
				}
			}
		}
	}
	if vulnLookup != nil {
		snapshot.WithVulnLookup(vulnLookup)
	}

	// License fetcher: disabled when AEGIS_NO_VULN_LOOKUP=1 (same offline
	// flag as vuln lookup — both hit external registries).
	if os.Getenv("AEGIS_NO_VULN_LOOKUP") == "" {
		snapshot.WithLicenseFetcher(licensefetch.New(
			npmregistry.New(npmregistry.WithHTTPClient(httpClient)),
			pypiregistry.New(pypiregistry.WithHTTPClient(httpClient)),
			cratesregistry.New(cratesregistry.WithHTTPClient(httpClient)),
			rubygemsregistry.New(rubygemsregistry.WithHTTPClient(httpClient)),
			nugetregistry.New(nugetregistry.WithHTTPClient(httpClient)),
		))

		// npm provenance attestation fetcher. Checks SLSA/publish attestations
		// during enrich and flags npm packages with no attestation record.
		// Same offline gate as vuln/license — requires registry network access.
		snapshot.WithProvenanceFetcher(
			npmattestations.New(npmattestations.WithHTTPClient(httpClient)),
		)
	}

	// Behaviour-based malware heuristics: suspicious install hooks,
	// obfuscated payloads, sketchy URL targets, binary droppers,
	// typosquat names. Pure-function adapter, no I/O — runs on the
	// same source bytes the AST scanner already fetched. Disable
	// with AEGIS_NO_HEURISTICS=1 (e.g. for pure A/B comparison vs
	// AST-only scoring).
	if os.Getenv("AEGIS_NO_HEURISTICS") == "" {
		snapshot.WithMalwareHeuristics(heuristicsAdapter{})
		// Maintainer-hijack heuristic also needs registry-side
		// metadata (publish-time + weekly-downloads). Wire the
		// npm Resolver as the MaintainerSignalFetcher (it
		// already has the per-ecosystem dispatch logic); non-npm
		// ecosystems get a zero-value signal so the heuristic
		// degrades gracefully there.
		snapshot.WithMaintainerSignalFetcher(resolver)

		// Tarball-drift heuristic compares the published npm tarball
		// to the upstream git tag's file tree. Opt-in via
		// AEGIS_DRIFT=1 for now — it adds one GitHub API call per
		// dep, so on a 5000-dep scan it'd burn the anonymous quota
		// fast. Pair with GITHUB_TOKEN for the 5000/hr cap.
		if os.Getenv("AEGIS_DRIFT") != "" {
			snapshot.WithRepoTreeFetcher(newRepoTreeAdapter())
			if os.Getenv("AEGIS_DRIFT_ALL") != "" {
				snapshot.WithRepoTreeFullSweep(true)
			}
		}
	}
	analyzePresenter := cli.NewAnalyzePresenter(presenter)
	analyze := usecase.NewAnalyze(analyzePresenter)
	if os.Getenv("AEGIS_NO_HEURISTICS") == "" {
		analyze.WithHeuristics(heuristicsAdapter{})
	}
	ciPresenter := cli.NewCIPresenter(presenter)
	ci := usecase.NewCI(snapshot, ciPresenter)
	recheckPresenter := cli.NewRecheckPresenter(presenter)
	recheck := usecase.NewRecheck(scanner, apiClient, recheckPresenter)
	explainPresenter := cli.NewExplainPresenter(presenter)
	explain := usecase.NewExplain(store, analyze, explainPresenter)
	hookPresenter := cli.NewHookPresenter(presenter)
	hook := usecase.NewHook(hookfs.New(), hookPresenter)
	sbom := usecase.NewSbom(store, clii.Version)
	if vulnLookup != nil {
		sbom.WithVulnLookup(vulnLookup)
	}
	actions := usecase.NewActions()

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
		Sbom:               sbom,
		Actions:            actions,
		API:                apiClient,
		Cache:              cache,
		Audit:              audit,
		Managers:           registeredPMs,
		AllowlistLoader:    allowlistLoader,
		AllowlistPresenter: cli.NewAllowlistPresenter(presenter),
		InvocationID:       invocationID,
	})
}
