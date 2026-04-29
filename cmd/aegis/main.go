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
	"fmt"
	"os"

	clii "github.com/qwexvf/aegis/services/cli/internal/interface/cli"

	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/envprobe"
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

	// Use cases.
	gate := usecase.NewInstallGate(resolver, apiClient, cache, audit, confirm, env, presenter)
	snapshot := usecase.NewSnapshot(store, scanner, cli.NewSnapshotPresenter(presenter), clii.Version)

	// Optionally attach the risk engine (AST scanner). The
	// implementation is selected at compile time via build tags;
	// see risk_engine.go (default) and risk_engine_off.go.
	attachRiskEngine(snapshot)

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
