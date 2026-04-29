// Package main is the composition root for the aegis CLI. It wires
// concrete adapters (infra/) into ports (usecase) and hands off to the
// CLI command tree. This is the ONLY file that constructs adapters —
// every other layer talks to ports, not implementations.
package main

import (
	clii "github.com/qwexvf/aegis/services/cli/internal/interface/cli"

	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/envprobe"
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

	// Use case.
	gate := usecase.NewInstallGate(resolver, apiClient, cache, audit, confirm, env, presenter)

	// PM wrappers (the order here drives `aegis --help` listing).
	managers := []pmwrapper.PackageManager{
		pmwrapper.NewNpm(),
		pmwrapper.NewBun(),
		pmwrapper.NewYarn(),
		pmwrapper.NewPnpm(),
	}

	clii.Execute(clii.Deps{
		Gate:     gate,
		Cache:    cache,
		Audit:    audit,
		Managers: managers,
	})
}
