package ast

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// manifestHooks reads ecosystem-specific manifest data and extracts
// install hooks (npm scripts.preinstall/postinstall/install,
// pip setup.py-existence, cargo build.rs-existence, etc.). Empty
// manifest → no hooks.
func manifestHooks(eco domain.Ecosystem, manifest []byte) []domain.InstallHook {
	if len(manifest) == 0 {
		return nil
	}
	switch eco {
	case domain.EcoNpm:
		return npmManifestHooks(manifest)
	}
	return nil
}

// npmManifestHooks parses package.json's "scripts" field. The npm
// docs list these as automatically run by `npm install`:
//
//	preinstall  — before deps installed
//	install     — after deps installed (synonymous w/ postinstall)
//	postinstall — after deps installed
//
// Source: https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts
//
// "prepare" runs after install too but only for git/local installs;
// we include it because supply-chain attackers have used it.
func npmManifestHooks(manifest []byte) []domain.InstallHook {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(manifest, &pkg); err != nil {
		return nil
	}
	if len(pkg.Scripts) == 0 {
		return nil
	}

	out := make([]domain.InstallHook, 0, 4)
	add := func(name string, phase domain.HookPhase) {
		body, ok := pkg.Scripts[name]
		if !ok || body == "" {
			return
		}
		sum := sha256.Sum256([]byte(body))
		out = append(out, domain.InstallHook{
			Phase:  phase,
			Source: "scripts." + name,
			Sha256: hex.EncodeToString(sum[:]),
		})
	}
	add("preinstall", domain.PhasePreInstall)
	add("install", domain.PhasePostInstall)
	add("postinstall", domain.PhasePostInstall)
	add("prepare", domain.PhasePostInstall)

	// Stable ordering for equality tests.
	slices.SortFunc(out, func(a, b domain.InstallHook) int {
		if a.Phase != b.Phase {
			return cmp.Compare(a.Phase, b.Phase)
		}
		return cmp.Compare(a.Source, b.Source)
	})
	return out
}
