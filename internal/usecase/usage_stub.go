//go:build nojsscan

// nojsscan build: depusage transitively requires cgo (go-tree-sitter
// core), so the AST-free flavour ships no-op AnalyzeUsage stubs to
// keep aegis-core pure-Go. Reachability data is simply omitted; all
// deps stay Unknown.

package usecase

import (
	"context"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
)

func AnalyzeUsage(ctx context.Context, projectDir string, snap *domain.Snapshot) error {
	return nil
}

func AnalyzeUsageWithCache(ctx context.Context, projectDir string, snap *domain.Snapshot, cache *diskcache.UsageCache) error {
	return nil
}
