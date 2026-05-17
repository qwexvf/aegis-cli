package image

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// findDep returns the first dep matching (eco, name) or zero+false.
func findDep(deps []domain.Dependency, eco domain.Ecosystem, name string) (domain.Dependency, bool) {
	for _, d := range deps {
		if d.Ecosystem == eco && d.Name == name {
			return d, true
		}
	}
	return domain.Dependency{}, false
}

func TestManifestWalk_NpmScopedAndUnscoped(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.17.21"}`)},
			{name: "app/node_modules/@types/node/package.json", body: []byte(`{"name":"@types/node","version":"20.0.0"}`)},
			// app-level package.json must NOT be picked up
			{name: "app/package.json", body: []byte(`{"name":"app","version":"1.0.0"}`)},
		}},
	}
	s := NewScanner()
	deps := runScan(t, s, layers, ScanOpts{})

	d, ok := findDep(deps, domain.EcoNpm, "lodash")
	if !ok || d.Version != "4.17.21" || d.Source != "manifest" {
		t.Errorf("lodash@4.17.21 missing or wrong (Source=%q version=%q): %v", d.Source, d.Version, deps)
	}
	if _, ok := findDep(deps, domain.EcoNpm, "@types/node"); !ok {
		t.Errorf("scoped @types/node missing: %v", deps)
	}
	if _, ok := findDep(deps, domain.EcoNpm, "app"); ok {
		t.Errorf("app-level package.json must NOT be synthesized: %v", deps)
	}
}

func TestManifestWalk_NpmOptTopLevel(t *testing.T) {
	// System-installed npm tooling that ships outside node_modules/ —
	// e.g. /opt/yarn-v1.22.22/package.json on node:20-alpine.
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "opt/yarn-v1.22.22/package.json", body: []byte(`{"name":"yarn","version":"1.22.22"}`)},
			// versionless /opt/<app>/ must NOT match
			{name: "opt/myapp/package.json", body: []byte(`{"name":"myapp","version":"1.0.0"}`)},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	d, ok := findDep(deps, domain.EcoNpm, "yarn")
	if !ok || d.Version != "1.22.22" || d.Source != "manifest" {
		t.Errorf("yarn@1.22.22 missing (Source=%q version=%q): %v", d.Source, d.Version, deps)
	}
	if _, ok := findDep(deps, domain.EcoNpm, "myapp"); ok {
		t.Errorf("versionless /opt/myapp/package.json must NOT be synthesized: %v", deps)
	}
}

func TestManifestWalk_PyPIDistInfo(t *testing.T) {
	metadata := []byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: HTTP for Humans\n\n")
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", body: metadata},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	d, ok := findDep(deps, domain.EcoPyPI, "requests")
	if !ok || d.Version != "2.31.0" || d.Source != "manifest" {
		t.Errorf("requests@2.31.0 missing (Source=%q version=%q): %v", d.Source, d.Version, deps)
	}
}

func TestManifestWalk_Rubygems(t *testing.T) {
	// Synthetic tar with a gem-dir entry. Most gem installs leave a
	// `gems/<name>-<ver>/` directory; we capture even without a manifest.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "usr/lib/ruby/gems/3.0.0/gems/rails-7.0.0/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "usr/lib/ruby/gems/3.0.0/gems/rails-7.0.0/lib/rails.rb", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	layers := []v1Layer{&fakeLayer{entries: tarballToEntries(buf.Bytes())}}

	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	d, ok := findDep(deps, domain.EcoRubyGems, "rails")
	if !ok || d.Version != "7.0.0" || d.Source != "manifest" {
		t.Errorf("rails@7.0.0 missing (Source=%q version=%q): %v", d.Source, d.Version, deps)
	}
}

func TestManifestWalk_PackagistComposer(t *testing.T) {
	composer := []byte(`{"name":"symfony/console","version":"6.0.0","require":{}}`)
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/vendor/symfony/console/composer.json", body: composer},
			// composer's own metadata dir must not be treated as a dep
			{name: "app/vendor/composer/installed.json", body: []byte(`{}`)},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	d, ok := findDep(deps, domain.EcoPackagist, "symfony/console")
	if !ok || d.Version != "6.0.0" || d.Source != "manifest" {
		t.Errorf("symfony/console missing (Source=%q version=%q): %v", d.Source, d.Version, deps)
	}
}

func TestManifestWalk_LockfileWinsOnCollision(t *testing.T) {
	// Same (npm, lodash, 4.17.21) reachable via lockfile AND manifest.
	// Lockfile entry must win — Source="lockfile" and DependsOn preserved.
	lock := []byte(`{
		"name": "x", "version": "1.0.0", "lockfileVersion": 3,
		"packages": {
			"": {"name":"x","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},
			"node_modules/lodash": {"version":"4.17.21","resolved":"https://example/","integrity":"sha512-abc","dependencies":{"underscore":"1.0.0"}},
			"node_modules/underscore": {"version":"1.0.0","resolved":"https://example/u","integrity":"sha512-def"}
		}
	}`)
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: lock},
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.17.21"}`)},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	d, ok := findDep(deps, domain.EcoNpm, "lodash")
	if !ok {
		t.Fatalf("lodash missing entirely: %v", deps)
	}
	if d.Source != "lockfile" {
		t.Errorf("lockfile should win on collision; got Source=%q", d.Source)
	}
	if d.Integrity == "" {
		t.Errorf("lockfile entry should keep Integrity; got empty")
	}
}

func TestManifestWalk_OverlayVersionWins(t *testing.T) {
	// Two layers: layer1 installs lodash@4.0.0, layer2 reinstalls 4.17.21.
	// Later manifest body wins; the resulting dep should reflect 4.17.21.
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.0.0"}`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.17.21"}`)},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	versions := make(map[string]struct{})
	for _, d := range deps {
		if d.Ecosystem == domain.EcoNpm && d.Name == "lodash" {
			versions[d.Version] = struct{}{}
		}
	}
	if _, ok := versions["4.17.21"]; !ok {
		t.Errorf("overlay-final version 4.17.21 missing; versions=%v deps=%v", versions, deps)
	}
	if _, ok := versions["4.0.0"]; ok {
		t.Errorf("earlier overlay version 4.0.0 should NOT survive; versions=%v", versions)
	}
}

func TestManifestWalk_OpaqueWhiteoutDropsDep(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.17.21"}`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh..wh..opq", body: nil},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{})
	if _, ok := findDep(deps, domain.EcoNpm, "lodash"); ok {
		t.Errorf("opaque whiteout on app/ should drop lodash manifest; got %v", deps)
	}
}

func TestManifestWalk_DisabledByFlag(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.17.21"}`)},
		}},
	}
	deps := runScan(t, NewScanner(), layers, ScanOpts{DisableManifestWalk: true})
	if _, ok := findDep(deps, domain.EcoNpm, "lodash"); ok {
		t.Errorf("manifest walker should be off; lodash must NOT be synthesized: %v", deps)
	}
}

func TestManifestWalk_TruncatedFlag(t *testing.T) {
	// Generate enough fake manifests to blow past maxTotalManifestBytes.
	// Each ~maxManifestFileBytes-1 bytes; need >64 MB worth.
	body := bytes.Repeat([]byte("x"), maxManifestFileBytes-128)
	// Pad to valid JSON-ish prefix so synthesizeNpm fails gracefully.
	// (synth-fail is fine; we're testing the byte-cap path.)
	body = append([]byte(`{"name":"p","version":"1.0.0"}`), body...)
	entries := make([]tarEntry, 0, 1100)
	for i := range 1100 {
		entries = append(entries, tarEntry{
			name: fmt.Sprintf("app/node_modules/p%d/package.json", i),
			body: body,
		})
	}
	layers := []v1Layer{&fakeLayer{entries: entries}}
	_, _, _, _, truncated, err := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Errorf("expected truncated=true after exceeding maxTotalManifestBytes, got false")
	}
}

// runScan runs the full ScanImagePackages flow over an in-memory image
// built from the given layers. Returns the resulting dep slice so each
// test can assert on Source / Version / presence without re-wiring the
// tarball + scanner pipeline.
func runScan(t *testing.T, s *Scanner, layers []v1Layer, opts ScanOpts) []domain.Dependency {
	t.Helper()
	files, pkgFiles, manifests, gemDirs, truncated, err := overlayLayersFull(layers, opts, s.lockfileNames)
	if err != nil {
		t.Fatal(err)
	}
	deps := s.parseFiles(files)
	if !opts.DisableManifestWalk {
		synth := synthesizeFromManifests(manifests, gemDirs)
		deps = mergeWithLockfile(deps, synth)
	}
	_ = pkgFiles
	_ = truncated
	return deps
}
