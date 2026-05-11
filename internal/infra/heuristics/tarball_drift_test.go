package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestDetectTarballDriftFromSources_Clean(t *testing.T) {
	cap, ev := DetectTarballDriftFromSources(
		[]byte(`{"name":"x","files":["dist"]}`),
		usecase.PackageSource{Files: map[string][]byte{
			"package/package.json": nil,
			"package/dist/x.js":    nil,
			"package/src/x.ts":     nil,
		}},
		[]string{"package.json", "src/x.ts"},
		"",
	)
	if cap != 0 || len(ev) != 0 {
		t.Errorf("expected no drift, got cap=%v ev=%v", cap, ev)
	}
}

func TestDetectTarballDriftFromSources_FlagsExtraCodeFile(t *testing.T) {
	cap, ev := DetectTarballDriftFromSources(
		[]byte(`{"name":"x"}`),
		usecase.PackageSource{Files: map[string][]byte{
			"package/package.json":     nil,
			"package/index.js":         nil,
			"package/telemetry/spy.js": nil, // not in repo
		}},
		[]string{"package.json", "index.js"},
		"",
	)
	if cap != domain.CapTarballDrift {
		t.Fatalf("expected CapTarballDrift, got %v", cap)
	}
	if len(ev) != 1 || ev[0].Path != "telemetry/spy.js" {
		t.Errorf("got ev=%v, want one entry for telemetry/spy.js", ev)
	}
}

func TestDetectTarballDriftFromSources_NoRepoFilesSkipsCleanly(t *testing.T) {
	// When the GitHub fetcher couldn't resolve a tag, repoFiles is nil.
	// We must NOT flag — that would punish every package without a
	// resolvable upstream.
	cap, _ := DetectTarballDriftFromSources(
		[]byte(`{"name":"x"}`),
		usecase.PackageSource{Files: map[string][]byte{
			"package/index.js": nil,
		}},
		nil,
		"",
	)
	if cap != 0 {
		t.Errorf("expected no signal when repoFiles empty, got %v", cap)
	}
}

func TestDetectTarballDriftFromSources_MonorepoSubdirMismatchSuppressed(t *testing.T) {
	// Tarball published from `packages/playwright-core/` but
	// package.json had no `repository.directory`. The detector
	// compares against the full monorepo tree → essentially every
	// tarball file looks "missing from repo". Without the cutoff
	// this becomes a false positive on every monorepo package; with
	// it, we skip cleanly.
	tarballFiles := map[string][]byte{
		"package/package.json":        nil,
		"package/index.js":            nil,
		"package/types/index.d.ts":    nil,
		"package/types/cli.d.ts":      nil,
		"package/types/foo.d.ts":      nil,
		"package/bin/run.js":          nil,
		"package/bin/setup.js":        nil,
		"package/internal/handler.js": nil,
		"package/internal/util.js":    nil,
		"package/internal/scan.js":    nil,
	}
	// Repo tree has packages/playwright/... but no packages/playwright-core,
	// so our detector can't find a matching subdir; without the cutoff
	// it would flag every tarball path as drifted.
	repoFiles := []string{
		"packages/playwright/src/index.js",
		"packages/playwright/src/cli.js",
		"README.md",
	}
	cap, _ := DetectTarballDriftFromSources(
		[]byte(`{"name":"playwright-core","version":"1.51.1"}`),
		usecase.PackageSource{Files: tarballFiles},
		repoFiles,
		"", // <- no directory hint
	)
	if cap != 0 {
		t.Errorf("expected drift suppression (high-ratio mismatch), got %v", cap)
	}
}

func TestDetectTarballDriftFromSources_ScriptFileFlaggedEvenWhenRatioHigh(t *testing.T) {
	// Even if everything looks drifted, a hook-referenced file
	// missing from the repo is high-signal — keep the flag.
	tarballFiles := map[string][]byte{
		"package/package.json": nil,
	}
	for i := range 30 {
		tarballFiles["package/extra"+string(rune('a'+i))+".js"] = nil
	}
	tarballFiles["package/.payload.js"] = nil // referenced by hook
	cap, _ := DetectTarballDriftFromSources(
		[]byte(`{"name":"x","scripts":{"postinstall":"node ./.payload.js"}}`),
		usecase.PackageSource{Files: tarballFiles},
		[]string{"package.json"},
		"",
	)
	if cap != domain.CapTarballDrift {
		t.Errorf("expected script-file flag despite high ratio, got %v", cap)
	}
}

func TestDetectTarballDriftFromSources_HookScriptFileMustExistInRepo(t *testing.T) {
	cap, ev := DetectTarballDriftFromSources(
		[]byte(`{
			"name":"x",
			"scripts":{"postinstall":"node ./install.js"}
		}`),
		usecase.PackageSource{Files: map[string][]byte{
			"package/package.json": nil,
			"package/install.js":   nil, // only in tarball
		}},
		[]string{"package.json"},
		"",
	)
	if cap != domain.CapTarballDrift {
		t.Fatalf("expected CapTarballDrift, got %v", cap)
	}
	if len(ev) != 1 || ev[0].Reason != "script-file" {
		t.Errorf("got ev=%v, want script-file:install.js", ev)
	}
}
