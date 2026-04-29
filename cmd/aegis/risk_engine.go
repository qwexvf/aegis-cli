//go:build !nojsscan

// Default build: AST risk engine compiled in (tree-sitter cgo + JS
// grammar + tarball fetcher). Adds ~3-4 MB to the binary.

package main

import (
	"fmt"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan/jsscan"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/jspkgsource"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

func attachRiskEngine(snapshot *usecase.Snapshot) {
	jsScanner, err := jsscan.New()
	if err != nil {
		// Embedded queries malformed = developer bug. Don't refuse to
		// run; degrade to no risk engine and warn.
		fmt.Fprintln(os.Stderr, "aegis: JS scanner init failed:", err)
		return
	}
	dispatcher := astscan.NewDispatcher()
	dispatcher.Register(domain.EcoNpm, jsScanner)

	snapshot.WithRiskEngine(
		jspkgsource.New(),
		dispatcher,
		diskcache.NewFingerprintCache(),
	)
}
