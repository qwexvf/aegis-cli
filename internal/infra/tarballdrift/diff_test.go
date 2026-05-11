package tarballdrift

import (
	"testing"
)

func TestDiff_CleanLodashLike(t *testing.T) {
	// "Clean" shape: tarball has src/ + dist/ + LICENSE; repo has src/.
	// dist/ is build output (whitelisted); LICENSE is docs.
	got := Diff(DiffInputs{
		TarballFiles: []string{
			"package.json",
			"README.md",
			"LICENSE",
			"src/index.js",
			"dist/index.js",
			"dist/index.cjs",
			"dist/index.d.ts",
		},
		RepoFiles: []string{
			"package.json",
			"README.md",
			"LICENSE",
			"src/index.js",
		},
	})
	if len(got) != 0 {
		t.Errorf("expected no drift, got %v", got)
	}
}

func TestDiff_DriftedExtraScriptFile(t *testing.T) {
	// Bad shape: postinstall references a file that's in the tarball
	// but not in the repo. Highest-signal drift.
	got := Diff(DiffInputs{
		TarballFiles: []string{
			"package.json",
			"index.js",
			"install.js", // <- only in tarball
		},
		RepoFiles: []string{
			"package.json",
			"index.js",
		},
		HookScripts: map[string]string{
			"postinstall": "node ./install.js",
		},
	})
	if len(got) != 1 || got[0].Path != "install.js" || got[0].Reason != "script-file" {
		t.Errorf("got %v, want one script-file:install.js", got)
	}
}

func TestDiff_DriftedExtraCodeFile(t *testing.T) {
	// Mid-signal: a .js file outside any whitelisted dir, not
	// referenced by a hook, but added at publish time.
	got := Diff(DiffInputs{
		TarballFiles: []string{
			"package.json",
			"src/index.js",
			"lib/extra-payload.js", // <- "lib" is build whitelist
			"telemetry/sneaky.js",  // <- not in repo, not whitelisted
		},
		RepoFiles: []string{
			"package.json",
			"src/index.js",
		},
	})
	// lib/ is a build dir → suppressed. telemetry/ is not → flagged.
	if len(got) != 1 || got[0].Path != "telemetry/sneaky.js" {
		t.Errorf("got %v, want one code-file:telemetry/sneaky.js", got)
	}
}

func TestDiff_PackageJSONFilesWhitelistSuppresses(t *testing.T) {
	got := Diff(DiffInputs{
		TarballFiles: []string{
			"package.json",
			"bundles/index.js",
		},
		RepoFiles: []string{
			"package.json",
		},
		PackageJSONFiles: []string{"bundles"},
	})
	if len(got) != 0 {
		t.Errorf("expected no drift (bundles/ whitelisted), got %v", got)
	}
}

func TestDiff_BinaryArtifactInTarballOnly(t *testing.T) {
	got := Diff(DiffInputs{
		TarballFiles: []string{
			"package.json",
			"bin/runtime.node", // <- ships native code; not in repo
		},
		RepoFiles: []string{
			"package.json",
		},
	})
	if len(got) != 1 || got[0].Reason != "binary-file" {
		t.Errorf("got %v, want one binary-file", got)
	}
}

func TestDiff_RepoSubdirStrippedForMonorepoPackages(t *testing.T) {
	// Tarball was published from `packages/core/`. The repo tree has
	// the file at `packages/core/src/index.js`; after stripping the
	// subdir it should match `src/index.js` in the tarball.
	got := Diff(DiffInputs{
		TarballFiles: []string{"src/index.js"},
		RepoFiles:    []string{"packages/core/src/index.js"},
		RepoSubdir:   "packages/core",
	})
	if len(got) != 0 {
		t.Errorf("expected subdir match (no drift), got %v", got)
	}
}

func TestDiff_EmptyInputsReturnNil(t *testing.T) {
	if got := Diff(DiffInputs{}); got != nil {
		t.Errorf("expected nil for empty inputs, got %v", got)
	}
}
