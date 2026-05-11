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

// RunMaintainerSignal is the second entry point — separated from
// Run because the input shape is different (registry metadata vs
// package source).
func (heuristicsAdapter) RunMaintainerSignal(sig domain.MaintainerSignal) []domain.Capability {
	return heuristics.RunMaintainerSignal(sig)
}

// RunTarballDrift is the third entry point. repoFiles=nil short-
// circuits to "no signal" so callers without a RepoTreeFetcher get
// the same behaviour as offline-mode runs.
func (heuristicsAdapter) RunTarballDrift(manifestRaw []byte, src usecase.PackageSource, repoFiles []string, repoSubdir string) domain.Capability {
	return heuristics.RunTarballDrift(manifestRaw, src, repoFiles, repoSubdir)
}
