package jspkgsource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// makeTarball builds an in-memory .tgz with the given files under a
// "package/" prefix (matching what npm publishes).
func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     "package/" + name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// fakeRegistry serves /pkg-name and /tarball-url paths.
func fakeRegistry(t *testing.T, name, version string, tarball []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"versions": map[string]any{
				version: map[string]any{
					"dist": map[string]any{
						// Filled in below; needs the test-server URL.
					},
				},
			},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(tarball)
	})
	srv := httptest.NewServer(mux)

	// Re-register the metadata handler with the actual tarball URL.
	mux.HandleFunc("/redo/"+name, func(w http.ResponseWriter, r *http.Request) {
		_ = r // unused, exists only to keep the second registration
	})
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"versions": map[string]any{
				version: map[string]any{
					"dist": map[string]any{
						"tarball": srv.URL + "/tarball.tgz",
					},
				},
			},
		})
	})
	mux2.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(tarball)
	})
	srv.Config.Handler = mux2
	return srv
}

func TestFetcher_FetchesAndExtracts(t *testing.T) {
	tarball := makeTarball(t, map[string]string{
		"package.json": `{"name":"demo","version":"1.0.0"}`,
		"index.js":     `module.exports = 1;`,
		"src/inner.js": `console.log('inner');`,
	})
	srv := fakeRegistry(t, "demo", "1.0.0", tarball)
	defer srv.Close()

	cacheDir := t.TempDir()
	f := New(WithRegistryURL(srv.URL), WithCacheDir(cacheDir))

	src, err := f.Fetch(context.Background(), domain.EcoNpm, "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if string(src.Manifest) != `{"name":"demo","version":"1.0.0"}` {
		t.Errorf("manifest lost: %q", src.Manifest)
	}
	if _, ok := src.Files["index.js"]; !ok {
		t.Errorf("index.js missing: %v", keys(src.Files))
	}
	if _, ok := src.Files["src/inner.js"]; !ok {
		t.Errorf("nested file missing: %v", keys(src.Files))
	}
}

func TestFetcher_ScopedPackageURLEscape(t *testing.T) {
	tarball := makeTarball(t, map[string]string{
		"package.json": `{"name":"@scope/demo","version":"1.0.0"}`,
	})
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/@scope%2fdemo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"versions": map[string]any{
				"1.0.0": map[string]any{
					"dist": map[string]any{"tarball": srv.URL + "/x.tgz"},
				},
			},
		})
	})
	mux.HandleFunc("/x.tgz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarball)
	})

	f := New(WithRegistryURL(srv.URL), WithCacheDir(t.TempDir()))
	src, err := f.Fetch(context.Background(), domain.EcoNpm, "@scope/demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if string(src.Manifest) != `{"name":"@scope/demo","version":"1.0.0"}` {
		t.Errorf("scoped fetch lost manifest: %q", src.Manifest)
	}
}

func TestFetcher_CachesBetweenCalls(t *testing.T) {
	tarball := makeTarball(t, map[string]string{
		"package.json": `{"name":"demo","version":"1.0.0"}`,
		"index.js":     `1`,
	})
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/demo" {
			hits++
			json.NewEncoder(w).Encode(map[string]any{
				"versions": map[string]any{
					"1.0.0": map[string]any{
						"dist": map[string]any{"tarball": "http://" + r.Host + "/x.tgz"},
					},
				},
			})
			return
		}
		w.Write(tarball)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	f := New(WithRegistryURL(srv.URL), WithCacheDir(cacheDir))

	if _, err := f.Fetch(context.Background(), domain.EcoNpm, "demo", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("first fetch hit count = %d, want 1", hits)
	}
	// Second call must hit the cache and skip the registry.
	if _, err := f.Fetch(context.Background(), domain.EcoNpm, "demo", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("second fetch hit count = %d, want still 1 (cached)", hits)
	}
}

func TestFetcher_RejectsNonNpmEcosystem(t *testing.T) {
	f := New(WithCacheDir(t.TempDir()))
	_, err := f.Fetch(context.Background(), domain.EcoPyPI, "demo", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "ecosystem") {
		t.Errorf("expected ecosystem-rejection error, got %v", err)
	}
}

func TestFetcher_FailsOnVersionNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{}})
	}))
	defer srv.Close()
	f := New(WithRegistryURL(srv.URL), WithCacheDir(t.TempDir()))
	_, err := f.Fetch(context.Background(), domain.EcoNpm, "demo", "9.9.9")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
}

func TestExtractTarball_SkipsOversizeFiles(t *testing.T) {
	big := strings.Repeat("x", 2*1024*1024) // 2 MiB
	tarball := makeTarball(t, map[string]string{
		"package.json": `{"name":"x","version":"1.0.0"}`,
		"big.js":       big,
	})
	src, err := extractTarball(tarball, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.Files["big.js"]; ok {
		t.Errorf("oversize file should have been skipped")
	}
	if _, ok := src.Files["package.json"]; !ok {
		t.Errorf("package.json should still be present")
	}
}

func TestCache_RejectsPathTraversal(t *testing.T) {
	// Build a tarball with a malicious entry, fetch it, then assert
	// that no file landed outside the per-package cache directory.
	tarball := makeTarball(t, map[string]string{
		"package.json":     `{"name":"demo","version":"1.0.0"}`,
		"../../etc/passwd": "should-not-be-written",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/demo" {
			json.NewEncoder(w).Encode(map[string]any{
				"versions": map[string]any{
					"1.0.0": map[string]any{
						"dist": map[string]any{"tarball": "http://" + r.Host + "/x.tgz"},
					},
				},
			})
			return
		}
		w.Write(tarball)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	f := New(WithRegistryURL(srv.URL), WithCacheDir(cacheDir))
	if _, err := f.Fetch(context.Background(), domain.EcoNpm, "demo", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	// Anything outside cacheDir/npm/demo/1.0.0 is a traversal.
	expectedRoot := filepath.Join(cacheDir, "npm", "demo", "1.0.0")
	err := filepath.WalkDir(cacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasPrefix(path, expectedRoot) {
			t.Errorf("file written outside expected root: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Helpers --------------------------------------------------------------

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = io.EOF // keep io imported for any future test additions
