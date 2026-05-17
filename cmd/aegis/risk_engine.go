// risk_engine.go wires the AST risk engine: tree-sitter (cgo) language
// scanners, the tarball fetcher, and the disk-backed fingerprint cache.
// Compiled into every aegis binary — all-in-one.

package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis-cli/internal/infra/jspkgsource"
	"github.com/qwexvf/aegis-cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis-cli/internal/infra/reporterid"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/csharp"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/gleam"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/golang"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/java"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/js"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/lua"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/php"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/py"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/ruby"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/rust"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// buildASTDispatcher returns the cross-language AST scanner dispatcher
// (tree-sitter scanners per ecosystem). Returns nil when the JS scanner
// — the only one that's truly required — fails to construct; callers
// must treat nil as "no risk engine available" and degrade gracefully.
//
// Extracted so multiple use cases (snapshot, analyze, image) can share
// one dispatcher with one HTTP pool and consistent ecosystem coverage.
func buildASTDispatcher() *ast.Dispatcher {
	jsScanner, err := js.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: JS scanner init failed:", err)
		return nil
	}
	dispatcher := ast.NewDispatcher()
	dispatcher.Register(domain.EcoNpm, jsScanner)

	tryRegister := func(name string, eco domain.Ecosystem, ctor func() (ast.LanguageScanner, error)) {
		s, err := ctor()
		if err != nil {
			fmt.Fprintf(os.Stderr, "aegis: %s scanner init failed: %v\n", name, err)
			return
		}
		dispatcher.Register(eco, s)
	}
	tryRegister("Python", domain.EcoPyPI, func() (ast.LanguageScanner, error) { return py.New() })
	tryRegister("Ruby", domain.EcoRubyGems, func() (ast.LanguageScanner, error) { return ruby.New() })
	tryRegister("Rust", domain.EcoCrates, func() (ast.LanguageScanner, error) { return rust.New() })
	tryRegister("Go", domain.EcoGo, func() (ast.LanguageScanner, error) { return golang.New() })
	tryRegister("Java", domain.EcoMaven, func() (ast.LanguageScanner, error) { return java.New() })
	tryRegister("PHP", domain.EcoPackagist, func() (ast.LanguageScanner, error) { return php.New() })
	tryRegister("C#", domain.EcoNuGet, func() (ast.LanguageScanner, error) { return csharp.New() })
	tryRegister("Gleam", domain.EcoGleam, func() (ast.LanguageScanner, error) { return gleam.New() })
	tryRegister("Lua", domain.EcoNeovim, func() (ast.LanguageScanner, error) { return lua.New() })
	return dispatcher
}

func attachRiskEngine(snapshot *usecase.Snapshot, analyze *usecase.Analyze, apiClient *aegisapi.Client, httpClient *http.Client) {
	dispatcher := buildASTDispatcher()
	if dispatcher == nil {
		return
	}

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
