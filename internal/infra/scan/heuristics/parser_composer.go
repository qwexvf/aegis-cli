package heuristics

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type composerParser struct{}

func (p *composerParser) Ecosystems() []domain.Ecosystem {
	return []domain.Ecosystem{domain.EcoPackagist}
}

func (p *composerParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoPackagist,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		if strings.ToLower(path.Base(filename)) == "composer.json" {
			deps, hooks := parseComposerJSON(body)
			pkg.Deps = append(pkg.Deps, deps...)
			pkg.Hooks = append(pkg.Hooks, hooks...)
		}
	}
	return pkg
}

// composerManifest is the subset of composer.json fields relevant to
// supply-chain risk detection.
type composerManifest struct {
	Name         string `json:"name"`
	Repositories []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"repositories"`
	// Scripts can be a string, []string, or {"phase": string|[]string}.
	// We decode the outer map; inner values are decoded on-demand.
	Scripts map[string]json.RawMessage `json:"scripts"`
}

// composerInstallPhases are the lifecycle hooks Composer runs automatically
// during `composer install` / `composer update`.
var composerInstallPhases = []string{
	"pre-install-cmd",
	"post-install-cmd",
	"pre-update-cmd",
	"post-update-cmd",
	"post-autoload-dump",
}

func parseComposerJSON(raw []byte) ([]Dep, []Hook) {
	var manifest composerManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, nil
	}
	var deps []Dep
	for _, repo := range manifest.Repositories {
		if strings.ToLower(repo.Type) == "vcs" {
			deps = append(deps, Dep{
				Name:   repo.URL,
				Spec:   repo.URL,
				Source: DepSourceVCS,
			})
		}
	}
	var hooks []Hook
	for _, phase := range composerInstallPhases {
		raw, ok := manifest.Scripts[phase]
		if !ok {
			continue
		}
		// Script can be a string or []string.
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			hooks = append(hooks, Hook{Phase: phase, Body: single})
			continue
		}
		var multi []string
		if err := json.Unmarshal(raw, &multi); err == nil {
			hooks = append(hooks, Hook{Phase: phase, Body: strings.Join(multi, "\n")})
		}
	}
	return deps, hooks
}
