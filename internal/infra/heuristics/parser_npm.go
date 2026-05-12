package heuristics

import (
	"encoding/json"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type npmParser struct{}

func (p *npmParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoNpm} }

func (p *npmParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoNpm,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	if len(manifestRaw) == 0 {
		return pkg
	}
	var manifest struct {
		Name                 string            `json:"name"`
		Scripts              map[string]string `json:"scripts"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return pkg
	}
	if manifest.Name != "" {
		pkg.Name = manifest.Name
	}

	addDeps := func(deps map[string]string, groups []string) {
		for depName, spec := range deps {
			pkg.Deps = append(pkg.Deps, Dep{
				Name:   depName,
				Spec:   spec,
				Source: classifyNPMDepSource(spec),
				Groups: groups,
			})
		}
	}
	addDeps(manifest.Dependencies, []string{"direct"})
	addDeps(manifest.DevDependencies, []string{"dev"})
	addDeps(manifest.PeerDependencies, []string{"peer"})
	addDeps(manifest.OptionalDependencies, []string{"optional"})

	// Install-time lifecycle hooks — the primary supply-chain attack surface.
	scripts := extractNpmScripts(manifestRaw)
	for _, phase := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if body, ok := scripts[phase]; ok && body != "" {
			pkg.Hooks = append(pkg.Hooks, Hook{Phase: phase, Body: body})
		}
	}
	return pkg
}

// classifyNPMDepSource returns the DepSource for an npm version spec.
func classifyNPMDepSource(spec string) DepSource {
	spec = strings.TrimSpace(spec)
	if isGitDepSpec(spec) {
		return DepSourceVCS
	}
	if strings.HasPrefix(spec, "file:") ||
		strings.HasPrefix(spec, "./") ||
		strings.HasPrefix(spec, "../") {
		return DepSourceLocal
	}
	return DepSourceRegistry
}
