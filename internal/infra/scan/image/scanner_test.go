package image

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// fakeLayer is an in-memory v1Layer for tests. Constructs a synthetic
// uncompressed tar stream from a map of path → bytes (or whiteouts).
type fakeLayer struct {
	entries []tarEntry
}

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
}

func (l *fakeLayer) Uncompressed() (io.ReadCloser, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range l.entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: e.typeflag,
		}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.body); err != nil {
			return nil, err
		}
	}
	_ = tw.Close()
	return io.NopCloser(&buf), nil
}

func TestOverlayLayers_AddsFiles(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"name":"x"}`)},
		}},
	}
	files, _, _, err := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["app/package-lock.json"]; !ok {
		t.Errorf("expected app/package-lock.json in overlay, got %v", keys(files))
	}
}

func TestOverlayLayers_LaterLayerOverwrites(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"v":1}`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"v":2}`)},
		}},
	}
	files, _, _, _ := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if string(files["app/package-lock.json"]) != `{"v":2}` {
		t.Errorf("later layer should win; got %q", files["app/package-lock.json"])
	}
}

func TestOverlayLayers_FileWhiteoutRemoves(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"v":1}`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh.package-lock.json", body: nil},
		}},
	}
	files, _, _, _ := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if _, ok := files["app/package-lock.json"]; ok {
		t.Errorf("whiteout should remove file; still present: %v", keys(files))
	}
}

func TestOverlayLayers_OpaqueDirWhiteoutClearsSubtree(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{}`)},
			{name: "app/sub/Gemfile.lock", body: []byte(`Gemfile`)},
			{name: "other/package-lock.json", body: []byte(`other`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh..wh..opq", body: nil},
		}},
	}
	files, _, _, _ := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if _, ok := files["app/package-lock.json"]; ok {
		t.Errorf("opaque whiteout should clear app/*; got %v", keys(files))
	}
	if _, ok := files["app/sub/Gemfile.lock"]; ok {
		t.Errorf("opaque whiteout should clear app/sub/*; got %v", keys(files))
	}
	if _, ok := files["other/package-lock.json"]; !ok {
		t.Errorf("opaque whiteout on app/ should NOT clear other/; got %v", keys(files))
	}
}

func TestOverlayLayers_ReintroductionAfterWhiteout(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`old`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh.package-lock.json", body: nil},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`new`)},
		}},
	}
	files, _, _, _ := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if string(files["app/package-lock.json"]) != "new" {
		t.Errorf("re-introduced file should win; got %q", files["app/package-lock.json"])
	}
}

func TestOverlayLayers_IgnoresNonCandidateFiles(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "etc/hostname", body: []byte(`host`)},
			{name: "var/log/syslog", body: bytes.Repeat([]byte("x"), 10*1024*1024)},
			{name: "app/package-lock.json", body: []byte(`{}`)},
		}},
	}
	files, _, _, _ := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	if len(files) != 1 {
		t.Errorf("only registered lockfile should be captured; got %v", keys(files))
	}
}

func TestOverlayLayers_FileSizeCap(t *testing.T) {
	// 5 MB file — should be truncated to maxFileBytes (4 MB).
	big := bytes.Repeat([]byte("x"), 5*1024*1024)
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: big},
		}},
	}
	files, _, _, _ := overlayLayersFull(layers, ScanOpts{}, defaultLockfileNames())
	body := files["app/package-lock.json"]
	if len(body) > maxFileBytes {
		t.Errorf("file size cap not enforced: got %d bytes, cap %d", len(body), maxFileBytes)
	}
}

func TestDedupSort_RemovesDuplicates(t *testing.T) {
	// Two layers both containing the same lockfile (e.g. multi-stage
	// build re-running `npm ci`) shouldn't double-count.
	deps := []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
		{Ecosystem: domain.EcoNpm, Name: "axios", Version: "1.0.0"},
	}
	out := dedupSort(deps)
	if len(out) != 2 {
		t.Errorf("expected 2 unique deps after dedup, got %d", len(out))
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- per-package source capture tests ----------------------------------

func TestPackageBoundary(t *testing.T) {
	tests := []struct {
		in      string
		wantKey string
		wantRel string
		wantOK  bool
	}{
		// --- npm ---
		{"node_modules/lodash/index.js", "npm/lodash", "index.js", true},
		{"node_modules/lodash/lib/foo.js", "npm/lodash", "lib/foo.js", true},
		{"app/node_modules/lodash/lib/foo.js", "npm/lodash", "lib/foo.js", true},
		{"node_modules/@types/node/index.d.ts", "npm/@types/node", "index.d.ts", true},
		{"node_modules/@scope/pkg/sub/file.js", "npm/@scope/pkg", "sub/file.js", true},
		{"node_modules/a/node_modules/b/index.js", "npm/b", "index.js", true},
		{"app/src/index.js", "", "", false},
		{"node_modules/lodash", "", "", false},

		// --- pypi ---
		{"usr/lib/python3.11/site-packages/requests/__init__.py", "pypi/requests", "__init__.py", true},
		{"usr/lib/python3.11/site-packages/requests/api.py", "pypi/requests", "api.py", true},
		// dist-info is metadata, NOT source
		{"usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", "", "", false},
		{"usr/lib/python3.11/site-packages/requests-2.31.0.egg-info/PKG-INFO", "", "", false},
		// __pycache__ excluded
		{"usr/lib/python3.11/site-packages/__pycache__/x.cpython-311.pyc", "", "", false},

		// --- rubygems ---
		{"usr/lib/ruby/gems/3.0.0/gems/rails-7.0.0/lib/rails.rb", "rubygems/rails@7.0.0", "lib/rails.rb", true},
		// Gem name with hyphens (rack-test): version is the LAST hyphen-prefix-digit segment
		{"gems/rack-test-2.0.0/lib/rack/test.rb", "rubygems/rack-test@2.0.0", "lib/rack/test.rb", true},
		// No version embedded → not a usable gem path
		{"gems/garbage/lib/x.rb", "", "", false},

		// --- packagist (composer) ---
		{"app/vendor/symfony/console/src/Command.php", "packagist/symfony/console", "src/Command.php", true},
		{"vendor/laravel/framework/src/Foundation/Application.php", "packagist/laravel/framework", "src/Foundation/Application.php", true},
		// composer's own metadata dirs excluded
		{"vendor/composer/autoload_real.php", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			key, rel, ok := packageBoundary(tt.in)
			if key != tt.wantKey || rel != tt.wantRel || ok != tt.wantOK {
				t.Errorf("packageBoundary(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.in, key, rel, ok, tt.wantKey, tt.wantRel, tt.wantOK)
			}
		})
	}
}

func TestIsSourceFile(t *testing.T) {
	source := []string{
		"index.js", "main.mjs", "a.cjs",
		"src/foo.ts", "src/foo.tsx",
		"app.py", "stub.pyi",
		"main.rb",
		"main.go", "main.rs",
		"App.java", "controller.php",
		"Program.cs",
		"package.json",
	}
	for _, f := range source {
		if !isSourceFile(f) {
			t.Errorf("expected %q to be a source file", f)
		}
	}
	notSource := []string{
		"README.md", "image.png", "data.csv", "ARCHITECTURE",
		"foo.bin", "x.so", "node_modules/foo/lib/index.js.map",
	}
	for _, f := range notSource {
		if isSourceFile(f) {
			t.Errorf("expected %q NOT to be a source file", f)
		}
	}
}

func TestScanImagePackages_CapturesPackageSources(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{
				"name": "test", "version": "1.0.0", "lockfileVersion": 3,
				"packages": {
					"": {"name":"test","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},
					"node_modules/lodash": {"version":"4.17.21","resolved":"...","integrity":"..."}
				}
			}`)},
			{name: "app/node_modules/lodash/package.json", body: []byte(`{"name":"lodash","version":"4.17.21"}`)},
			{name: "app/node_modules/lodash/index.js", body: []byte(`eval("evil()");`)},
			{name: "app/node_modules/lodash/README.md", body: []byte(`# lodash`)}, // not a source file, skipped
		}},
	}
	files, pkgFiles, _, err := overlayLayersFull(layers, ScanOpts{CapturePackageSources: true}, defaultLockfileNames())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["app/package-lock.json"]; !ok {
		t.Errorf("lockfile not captured")
	}
	lodash, ok := pkgFiles["npm/lodash"]
	if !ok {
		t.Fatalf("npm/lodash package not captured; got keys: %v", pkgKeys(pkgFiles))
	}
	if _, ok := lodash["index.js"]; !ok {
		t.Errorf("lodash/index.js missing; got: %v", fileKeys(lodash))
	}
	if _, ok := lodash["package.json"]; !ok {
		t.Errorf("lodash/package.json missing (needed for manifest)")
	}
	if _, ok := lodash["README.md"]; ok {
		t.Errorf("README.md should NOT be captured (not a source file)")
	}
}

func TestScanImagePackages_CapturesDisabledWhenFlagOff(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/node_modules/lodash/index.js", body: []byte(`eval("x");`)},
		}},
	}
	_, pkgFiles, _, err := overlayLayersFull(layers, ScanOpts{CapturePackageSources: false}, defaultLockfileNames())
	if err != nil {
		t.Fatal(err)
	}
	if pkgFiles != nil {
		t.Errorf("pkgFiles should be nil when CapturePackageSources=false; got %d entries", len(pkgFiles))
	}
}

func TestStashPackageSource_CapHonored(t *testing.T) {
	pkgFiles := make(map[string]map[string][]byte)
	pkgSize := make(map[string]int)

	// 3 MB first file — captured.
	body1 := make([]byte, 3*1024*1024)
	stashPackageSource("node_modules/big/a.js", body1, pkgFiles, pkgSize)
	if _, ok := pkgFiles["npm/big"]["a.js"]; !ok {
		t.Fatal("first file should fit under cap")
	}
	// 2 MB second file — would exceed 4 MB cap, dropped.
	body2 := make([]byte, 2*1024*1024)
	stashPackageSource("node_modules/big/b.js", body2, pkgFiles, pkgSize)
	if _, ok := pkgFiles["npm/big"]["b.js"]; ok {
		t.Errorf("second file should be dropped to honour maxPackageBytes cap")
	}
}

// TestOverlayLayers_GlobalLockfileCap_SetsTruncated forces the merge
// step past maxTotalLockfileBytes by feeding many large lockfiles and
// asserts the truncated bool is surfaced. Regression guard for silent
// data loss on adversarial / oversized images.
func TestOverlayLayers_GlobalLockfileCap_SetsTruncated(t *testing.T) {
	// 70 lockfiles × 4 MB each = 280 MB > 256 MB cap.
	body := bytes.Repeat([]byte("x"), maxFileBytes)
	entries := make([]tarEntry, 0, 70)
	for i := range 70 {
		entries = append(entries, tarEntry{
			name: fmt.Sprintf("app%d/package-lock.json", i),
			body: body,
		})
	}
	_, _, truncated, err := overlayLayersFull([]v1Layer{&fakeLayer{entries: entries}}, ScanOpts{}, defaultLockfileNames())
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Errorf("expected truncated=true after exceeding maxTotalLockfileBytes, got false")
	}
}

func pkgKeys(m map[string]map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func fileKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
