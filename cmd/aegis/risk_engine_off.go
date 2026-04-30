//go:build nojsscan

// `nojsscan` build: AST risk engine omitted. The binary doesn't link
// tree-sitter (cgo) or the JS grammar package. `aegis snapshot
// enrich` still works as a CLI command but reports that the risk
// engine isn't available.
//
// Use case: size-constrained CI runners that only need install-gate
// + incident-DB lookup. Saves ~3-4 MB and removes the cgo dependency.

package main

import (
	"net/http"

	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

func attachRiskEngine(_ *usecase.Snapshot, _ *aegisapi.Client, _ *http.Client) {
	// no-op: snapshot.WithRiskEngine never called, so Enrich/Diff
	// will report "risk engine not configured". Submit reports the
	// same configuration error.
}
