package heuristics

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/tarballdrift"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// DetectTarballDriftFromSources runs the pure tarballdrift.Diff over
// the package's tarball + the upstream repo file list, returning
// CapTarballDrift when paths in the tarball are missing from the repo
// and not covered by the standard build-output whitelist.
//
// Inputs are kept narrow on purpose so the function stays testable
// without network access. Snapshot.Enrich does the actual fetches and
// hands the results in. When repoFiles is empty (caller couldn't
// resolve repo or tag), the heuristic returns 0 — "no signal", not
// "no drift".
//
// The first return value is the Capability (0 if no drift found);
// the second is the list of evidence paths for the explain renderer.
func DetectTarballDriftFromSources(
	manifestRaw []byte,
	src usecase.PackageSource,
	repoFiles []string,
	repoSubdir string,
) (domain.Capability, []tarballdrift.DriftEvidence) {
	if len(repoFiles) == 0 || len(src.Files) == 0 {
		return 0, nil
	}

	tarballPaths := make([]string, 0, len(src.Files))
	for p := range src.Files {
		// Strip npm's "package/" prefix if the adapter didn't.
		// Belt-and-suspenders: callers normalize, but tests pass
		// raw maps so we double-check.
		rest, ok := strings.CutPrefix(p, "package/")
		if ok {
			tarballPaths = append(tarballPaths, rest)
		} else {
			tarballPaths = append(tarballPaths, p)
		}
	}

	hooks := extractNpmScripts(manifestRaw)
	pkgFiles := extractPackageFilesField(manifestRaw)

	ev := tarballdrift.Diff(tarballdrift.DiffInputs{
		TarballFiles:     tarballPaths,
		RepoFiles:        repoFiles,
		PackageJSONFiles: pkgFiles,
		HookScripts:      hooks,
		RepoSubdir:       repoSubdir,
	})
	if len(ev) == 0 {
		return 0, nil
	}
	// Confidence cutoff for non-script evidence: when too many tarball
	// paths look "drifted" the more likely explanation is a monorepo
	// whose subdir we couldn't resolve (package.json had no
	// `repository.directory` and our heuristic guess didn't land).
	// Real published-payload drift is a few extra files smuggled into
	// an otherwise-matching tarball, not a wholesale mismatch.
	//
	// Script-file evidence (install-hook references a file that exists
	// only in the tarball) is the highest-signal shape we look for —
	// it's also robust to subdir mismatch because install hooks don't
	// reference monorepo-sibling paths. Always flag when present.
	if hasScriptFileEvidence(ev) {
		return domain.CapTarballDrift, ev
	}
	if isLikelyMonorepoSubdirMismatch(ev, tarballPaths) {
		return 0, nil
	}
	return domain.CapTarballDrift, ev
}

func hasScriptFileEvidence(ev []tarballdrift.DriftEvidence) bool {
	for _, e := range ev {
		if e.Reason == "script-file" {
			return true
		}
	}
	return false
}

// isLikelyMonorepoSubdirMismatch returns true when the drift count is
// large enough relative to the tarball that the cause is almost
// certainly "we compared against the wrong subdir of a monorepo",
// not "real publish-time payload". Mismatch makes every tarball file
// look drifted; real publish-payloads add 1–4 files to a 40+ file
// tarball.
//
// Decision: a small absolute drift (≤4 files) is always real signal.
// Above that, fall back to a 30% ratio cutoff against the count of
// code-ish files in the tarball.
func isLikelyMonorepoSubdirMismatch(ev []tarballdrift.DriftEvidence, tarballPaths []string) bool {
	const smallDriftCutoff = 4
	const ratioThreshold = 0.30

	if len(ev) <= smallDriftCutoff {
		return false
	}
	considered := 0
	for _, p := range tarballPaths {
		switch strings.ToLower(path.Ext(p)) {
		case ".js", ".mjs", ".cjs", ".ts", ".json", ".node", ".so", ".wasm":
			considered++
		}
	}
	if considered == 0 {
		return false
	}
	return float64(len(ev))/float64(considered) > ratioThreshold
}

// extractPackageFilesField pulls the package.json "files" whitelist
// (the patterns npm publish uses to pick what ends up in the tarball).
// Returns nil on parse failure — the diff treats that as "no whitelist",
// not "empty whitelist", so missing files in package.json don't
// suppress real signals.
func extractPackageFilesField(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var pkg struct {
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil
	}
	return pkg.Files
}
