//go:build !nojsscan

// Default build: AST risk engine compiled in (tree-sitter cgo + JS
// grammar + tarball fetcher). Adds ~3-4 MB to the binary.

package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/goscan"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/jsscan"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/pyscan"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/rbscan"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan/rsscan"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis-cli/internal/infra/jspkgsource"
	"github.com/qwexvf/aegis-cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/reporterid"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func attachRiskEngine(snapshot *usecase.Snapshot, analyze *usecase.Analyze, apiClient *aegisapi.Client, httpClient *http.Client) {
	jsScanner, err := jsscan.New()
	if err != nil {
		// Embedded queries malformed = developer bug. Don't refuse to
		// run; degrade to no risk engine and warn.
		fmt.Fprintln(os.Stderr, "aegis: JS scanner init failed:", err)
		return
	}
	dispatcher := astscan.NewDispatcher()
	dispatcher.Register(domain.EcoNpm, jsScanner)

	// Non-JS scanners are best-effort: a constructor failure means the
	// embedded queries don't compile (developer bug), but the rest of
	// the gate (OSV lookup, source-pattern heuristics, install-hook
	// detection) still runs for those ecosystems. Warn and continue.
	tryRegister := func(name string, eco domain.Ecosystem, ctor func() (astscan.LanguageScanner, error)) {
		s, err := ctor()
		if err != nil {
			fmt.Fprintf(os.Stderr, "aegis: %s scanner init failed: %v\n", name, err)
			return
		}
		dispatcher.Register(eco, s)
	}
	tryRegister("Python", domain.EcoPyPI, func() (astscan.LanguageScanner, error) { return pyscan.New() })
	tryRegister("Ruby", domain.EcoRubyGems, func() (astscan.LanguageScanner, error) { return rbscan.New() })
	tryRegister("Rust", domain.EcoCrates, func() (astscan.LanguageScanner, error) { return rsscan.New() })
	tryRegister("Go", domain.EcoGo, func() (astscan.LanguageScanner, error) { return goscan.New() })

	fetcher := jspkgsource.New(jspkgsource.WithHTTPClient(httpClient))
	snapshot.WithRiskEngine(
		fetcher,
		dispatcher,
		diskcache.NewFingerprintCache(),
	)
	snapshot.WithSubmitter(dispatcher, apiClient, reporterid.New())
	// Optional provenance: best-effort lookup of npm publish time. The
	// resolver is its own object (not the install-gate's resolver) so
	// the submit pipeline doesn't share a packument cache with the
	// hot-path version resolver.
	snapshot.WithPublishedAtResolver(npmregistry.NewResolver(npmregistry.WithHTTPClient(httpClient)))

	// Analyze shares the same fetcher + dispatcher — one composition
	// root, one HTTP pool, one tarball cache across both use cases.
	if analyze != nil {
		analyze.WithRiskEngine(fetcher, dispatcher)
	}
}
