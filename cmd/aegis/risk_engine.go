//go:build !nojsscan

// Default build: AST risk engine compiled in (tree-sitter cgo + JS
// grammar + tarball fetcher). Adds ~3-4 MB to the binary.

package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan/jsscan"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/jspkgsource"
	"github.com/qwexvf/aegis/services/cli/internal/infra/npmregistry"
	"github.com/qwexvf/aegis/services/cli/internal/infra/reporterid"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

func attachRiskEngine(snapshot *usecase.Snapshot, apiClient *aegisapi.Client, httpClient *http.Client) {
	jsScanner, err := jsscan.New()
	if err != nil {
		// Embedded queries malformed = developer bug. Don't refuse to
		// run; degrade to no risk engine and warn.
		fmt.Fprintln(os.Stderr, "aegis: JS scanner init failed:", err)
		return
	}
	dispatcher := astscan.NewDispatcher()
	dispatcher.Register(domain.EcoNpm, jsScanner)

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
}
