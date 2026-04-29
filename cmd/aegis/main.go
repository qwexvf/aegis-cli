// Package main is the composition root for the aegis CLI. It wires
// concrete adapters (infra/) into ports (usecase) and hands off to the
// CLI command tree. This is the ONLY file that constructs adapters —
// every other layer talks to ports, not implementations.
package main

import (
	"fmt"
	"os"

	clii "github.com/qwexvf/aegis/services/cli/internal/interface/cli"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan/jsscan"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/envprobe"
	"github.com/qwexvf/aegis/services/cli/internal/infra/jspkgsource"
	"github.com/qwexvf/aegis/services/cli/internal/infra/locksnap"
	"github.com/qwexvf/aegis/services/cli/internal/infra/ndjsonaudit"
	"github.com/qwexvf/aegis/services/cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis/services/cli/internal/infra/pmwrapper"
	"github.com/qwexvf/aegis/services/cli/internal/infra/ttyprompt"
	"github.com/qwexvf/aegis/services/cli/internal/presenter/cli"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

func main() {
	// Adapters.
	resolver := npmregistry.NewResolver()
	apiClient := aegisapi.New()
	cache := diskcache.New()
	audit := ndjsonaudit.New()
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

	// Risk-engine adapters: AST scanner + tarball fetcher + cache.
	// Failure to compile the JS scanner means the embedded queries
	// are malformed (a developer bug); fall back to no risk engine
	// rather than refusing to run at all.
	jsScanner, jsErr := jsscan.New()
	dispatcher := astscan.NewDispatcher()
	if jsErr == nil {
		dispatcher.Register(domain.EcoNpm, jsScanner)
	} else {
		fmt.Fprintln(os.Stderr, "aegis: JS scanner init failed:", jsErr)
	}
	fetcher := jspkgsource.New()
	fpCache := diskcache.NewFingerprintCache()

	// Use cases.
	gate := usecase.NewInstallGate(resolver, apiClient, cache, audit, confirm, env, presenter)
	snapshot := usecase.NewSnapshot(store, scanner, cli.NewSnapshotPresenter(presenter), clii.Version)
	if jsErr == nil {
		snapshot.WithRiskEngine(fetcher, dispatcher, fpCache)
	}

	// PM wrappers (the order here drives `aegis --help` listing).
	managers := []pmwrapper.PackageManager{
		pmwrapper.NewNpm(),
		pmwrapper.NewBun(),
		pmwrapper.NewYarn(),
		pmwrapper.NewPnpm(),
	}

	clii.Execute(clii.Deps{
		Gate:     gate,
		Snapshot: snapshot,
		Cache:    cache,
		Audit:    audit,
		Managers: managers,
	})
}
