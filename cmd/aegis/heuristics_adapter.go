package main

import (
	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/heuristics"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// heuristicsAdapter is the trivial bridge from the usecase port
// (MalwareHeuristics) to the package-level heuristics.Run function.
// Lives in cmd/ because the composition root is the only place
// allowed to construct concrete adapters; usecase doesn't know about
// the heuristics package.
//
// Stateless — same instance is safe for concurrent use across the
// AST worker pool.
type heuristicsAdapter struct{}

func (heuristicsAdapter) Run(eco domain.Ecosystem, name string, manifestRaw []byte, src usecase.PackageSource) []domain.Capability {
	return heuristics.Run(eco, name, manifestRaw, src)
}
