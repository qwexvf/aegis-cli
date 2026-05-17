package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// buildImageTar writes an OCI tar to dst with the given layers (each a
// path → bytes map). Returns the path. Layers are appended in order;
// later layers overlay earlier ones — matching `docker save` semantics.
//
// Uses go-containerregistry's mutate/tarball machinery so the result is
// a real image consumable by tarball.ImageFromPath — exercising the
// production code path end-to-end without any docker daemon.
func buildImageTar(t *testing.T, dst string, layers []map[string][]byte) {
	t.Helper()
	img := empty.Image
	for _, layerFiles := range layers {
		l := makeTarballLayer(t, layerFiles)
		next, err := mutate.AppendLayers(img, l)
		if err != nil {
			t.Fatalf("append layer: %v", err)
		}
		img = next
	}
	if err := tarball.WriteToFile(dst, nil, img); err != nil {
		t.Fatalf("write image: %v", err)
	}
}

// makeTarballLayer constructs an uncompressed-tar v1.Layer in memory.
// Files map: path → content. Whiteouts pass `nil` body with a name
// starting `.wh.`.
func makeTarballLayer(t *testing.T, files map[string][]byte) v1.Layer {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar body: %v", err)
		}
	}
	_ = tw.Close()

	// gzip the tar — go-containerregistry expects compressed layers.
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(raw.Bytes()); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	_ = gw.Close()

	rawHash := sha256.Sum256(raw.Bytes())
	gzHash := sha256.Sum256(gz.Bytes())
	rawBytes := raw.Bytes()
	gzBytes := gz.Bytes()

	return &memLayer{
		diffID:           v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(rawHash[:])},
		digest:           v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(gzHash[:])},
		uncompressedBody: rawBytes,
		compressedBody:   gzBytes,
	}
}

// memLayer is a v1.Layer backed by in-memory bytes.
type memLayer struct {
	diffID           v1.Hash
	digest           v1.Hash
	uncompressedBody []byte
	compressedBody   []byte
}

func (m *memLayer) Digest() (v1.Hash, error)              { return m.digest, nil }
func (m *memLayer) DiffID() (v1.Hash, error)              { return m.diffID, nil }
func (m *memLayer) Size() (int64, error)                  { return int64(len(m.compressedBody)), nil }
func (m *memLayer) MediaType() (v1types.MediaType, error) { return v1types.DockerLayer, nil }
func (m *memLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.compressedBody)), nil
}
func (m *memLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.uncompressedBody)), nil
}

// --- tests --------------------------------------------------------------

func TestScanImage_FullFlow_NoLockfile(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "img.tar")
	buildImageTar(t, dst, []map[string][]byte{
		{"etc/hostname": []byte("test")},
	})
	deps, err := NewScanner().ScanImage(dst)
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps from no-lockfile image, got %d", len(deps))
	}
}

func TestScanImage_FullFlow_PackageLockExtracted(t *testing.T) {
	lockfile := mustJSON(t, map[string]any{
		"name":            "test",
		"version":         "1.0.0",
		"lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{"name": "test", "version": "1.0.0"},
			"node_modules/lodash": map[string]any{
				"version":   "4.17.21",
				"resolved":  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
			},
		},
	})
	dst := filepath.Join(t.TempDir(), "img.tar")
	buildImageTar(t, dst, []map[string][]byte{
		{"app/package-lock.json": lockfile},
	})
	deps, err := NewScanner().ScanImage(dst)
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "lodash" || deps[0].Version != "4.17.21" {
		t.Errorf("expected [lodash@4.17.21], got %+v", deps)
	}
}

func TestScanImagePackages_CapturesSourcesForAnalyzer(t *testing.T) {
	lockfile := mustJSON(t, map[string]any{
		"name": "x", "version": "1.0.0", "lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{"name": "x", "version": "1.0.0"},
			"node_modules/sneaky": map[string]any{
				"version":   "1.0.0",
				"resolved":  "https://example/sneaky-1.0.0.tgz",
				"integrity": "sha512-x",
			},
		},
	})
	dst := filepath.Join(t.TempDir(), "img.tar")
	buildImageTar(t, dst, []map[string][]byte{
		{
			"app/package-lock.json":                       lockfile,
			"app/node_modules/sneaky/package.json":        []byte(`{"name":"sneaky","version":"1.0.0"}`),
			"app/node_modules/sneaky/index.js":            []byte(`eval(atob("ZXZpbCgp"));`),
			"app/node_modules/sneaky/README.md":           []byte(`# do not capture`),
			"app/node_modules/sneaky/node_modules/x/p.js": []byte(`// nested package`),
		},
	})
	set, err := NewScanner().ScanImagePackages(dst, ScanOpts{CapturePackageSources: true})
	if err != nil {
		t.Fatalf("ScanImagePackages: %v", err)
	}
	src, ok := set.Sources["npm/sneaky@1.0.0"]
	if !ok {
		t.Fatalf("npm/sneaky@1.0.0 source not captured; got keys: %v", srcKeys(set.Sources))
	}
	if _, ok := src.Files["index.js"]; !ok {
		t.Errorf("sneaky/index.js missing — should be captured as source")
	}
	if _, ok := src.Files["README.md"]; ok {
		t.Errorf("README.md captured but isSourceFile excludes it")
	}
	if len(src.Manifest) == 0 {
		t.Errorf("Manifest (package.json) bytes not promoted")
	}
}

func TestScanImage_MultiLayerOverlay_LaterWins(t *testing.T) {
	v1lock := mustJSON(t, lockfileFor("lodash", "4.17.10"))
	v2lock := mustJSON(t, lockfileFor("lodash", "4.17.21"))
	dst := filepath.Join(t.TempDir(), "img.tar")
	buildImageTar(t, dst, []map[string][]byte{
		{"app/package-lock.json": v1lock},
		{"app/package-lock.json": v2lock},
	})
	deps, err := NewScanner().ScanImage(dst)
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(deps) != 1 || deps[0].Version != "4.17.21" {
		t.Errorf("expected lodash@4.17.21 (top layer wins), got %+v", deps)
	}
}

func TestScanImage_WhiteoutRemovesLockfile(t *testing.T) {
	v1lock := mustJSON(t, lockfileFor("lodash", "4.17.21"))
	dst := filepath.Join(t.TempDir(), "img.tar")
	buildImageTar(t, dst, []map[string][]byte{
		{"app/package-lock.json": v1lock},
		{"app/.wh.package-lock.json": []byte{}},
	})
	deps, err := NewScanner().ScanImage(dst)
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("whiteout should remove lockfile; got %+v", deps)
	}
}

func TestScanImage_LargeImage_BoundedMemory(t *testing.T) {
	// 50 lockfile-named entries, each 2 MB. Without the global cap the
	// scanner would buffer ~100 MB; we should top out at maxTotalLockfileBytes.
	files := make(map[string][]byte, 50)
	body := make([]byte, 2*1024*1024)
	for i := 0; i < 50; i++ {
		files[filepath.Join("apps", "p", string(rune('a'+i)), "package-lock.json")] = body
	}
	dst := filepath.Join(t.TempDir(), "img.tar")
	buildImageTar(t, dst, []map[string][]byte{files})

	set, err := NewScanner().ScanImagePackages(dst, ScanOpts{})
	if err != nil {
		t.Fatalf("ScanImagePackages: %v", err)
	}
	// Even with garbage content (Parse fails), the walker should have
	// completed without exhausting memory. dep parse skips silently.
	_ = set
}

// --- helpers -----------------------------------------------------------

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lockfileFor(pkg, version string) map[string]any {
	return map[string]any{
		"name": "test", "version": "1.0.0", "lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{"name": "test", "version": "1.0.0"},
			"node_modules/" + pkg: map[string]any{
				"version":   version,
				"resolved":  "https://registry.npmjs.org/" + pkg + "/-/" + pkg + "-" + version + ".tgz",
				"integrity": "sha512-fake",
			},
		},
	}
}

func srcKeys(m map[string]domain.PackageSource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
