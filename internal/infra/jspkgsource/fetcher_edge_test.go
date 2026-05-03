package jspkgsource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// makeTarballTyped builds a tarball where the caller controls each
// entry's tar.Header (lets us inject symlinks, dirs, oversize, etc.).
func makeTarballTyped(t *testing.T, entries []tar.Header, bodies map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, hdr := range entries {
		body := bodies[hdr.Name]
		hdr.Size = int64(len(body))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			tw.Write([]byte(body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractTarball_SkipsSymlinkAndDirEntries(t *testing.T) {
	tarball := makeTarballTyped(t, []tar.Header{
		{Name: "package/", Typeflag: tar.TypeDir},
		{Name: "package/index.js", Typeflag: tar.TypeReg},
		{Name: "package/symlink.js", Typeflag: tar.TypeSymlink, Linkname: "../../../etc/passwd"},
		{Name: "package/hardlink.js", Typeflag: tar.TypeLink, Linkname: "package/index.js"},
	}, map[string]string{
		"package/index.js": "module.exports = 1;",
	})

	src, err := extractTarball(tarball, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.Files["index.js"]; !ok {
		t.Errorf("regular file should be extracted, got files: %v", keys(src.Files))
	}
	for _, bad := range []string{"symlink.js", "hardlink.js"} {
		if _, ok := src.Files[bad]; ok {
			t.Errorf("non-regular file %q should be skipped", bad)
		}
	}
}

func TestExtractTarball_ZeroLengthFileKept(t *testing.T) {
	tarball := makeTarballTyped(t, []tar.Header{
		{Name: "package/empty.js", Typeflag: tar.TypeReg},
	}, map[string]string{"package/empty.js": ""})

	src, err := extractTarball(tarball, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	body, ok := src.Files["empty.js"]
	if !ok {
		t.Errorf("empty.js missing")
	}
	if len(body) != 0 {
		t.Errorf("expected zero-length, got %d bytes", len(body))
	}
}

func TestExtractTarball_ManifestPopulatedFromPackageJSON(t *testing.T) {
	tarball := makeTarballTyped(t, []tar.Header{
		{Name: "package/package.json", Typeflag: tar.TypeReg},
		{Name: "package/index.js", Typeflag: tar.TypeReg},
	}, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
		"package/index.js":     "module.exports = 1;",
	})
	src, err := extractTarball(tarball, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(src.Manifest) != `{"name":"x","version":"1.0.0"}` {
		t.Errorf("manifest not picked up: %q", src.Manifest)
	}
}

func TestExtractTarball_NoPackageJSONMeansEmptyManifest(t *testing.T) {
	tarball := makeTarballTyped(t, []tar.Header{
		{Name: "package/index.js", Typeflag: tar.TypeReg},
	}, map[string]string{"package/index.js": "1"})

	src, _ := extractTarball(tarball, 1024*1024)
	if len(src.Manifest) != 0 {
		t.Errorf("expected empty manifest, got %q", src.Manifest)
	}
	if _, ok := src.Files["index.js"]; !ok {
		t.Errorf("index.js missing")
	}
}

func TestExtractTarball_MalformedGzipReturnsError(t *testing.T) {
	_, err := extractTarball([]byte("not gzipped"), 1024*1024)
	if err == nil {
		t.Error("expected gunzip error")
	}
}

func TestExtractTarball_StripsAlternateRootPrefix(t *testing.T) {
	// Some non-standard tarballs use a different root dir; we strip
	// the first path component as a fallback.
	tarball := makeTarballTyped(t, []tar.Header{
		{Name: "weirdroot/index.js", Typeflag: tar.TypeReg},
	}, map[string]string{"weirdroot/index.js": "1"})
	src, _ := extractTarball(tarball, 1024*1024)
	if _, ok := src.Files["index.js"]; !ok {
		t.Errorf("expected stripped path 'index.js', got %v", keys(src.Files))
	}
}

func TestFetcher_MetadataNon200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	f := New(WithRegistryURL(srv.URL), WithCacheDir(t.TempDir()))
	_, err := f.Fetch(context.Background(), domain.EcoNpm, "missing", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("expected HTTP 404 error, got %v", err)
	}
}

func TestFetcher_TarballNon200Errors(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		// Return metadata pointing at a 500-ing tarball URL.
		w.Write([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"` + srv.URL + `/broken.tgz"}}}}`))
	})
	mux.HandleFunc("/broken.tgz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	f := New(WithRegistryURL(srv.URL), WithCacheDir(t.TempDir()))
	_, err := f.Fetch(context.Background(), domain.EcoNpm, "p", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected tarball HTTP 500 error, got %v", err)
	}
}

func TestFetcher_MissingNameOrVersionRejected(t *testing.T) {
	f := New(WithRegistryURL("http://unused"), WithCacheDir(t.TempDir()))
	if _, err := f.Fetch(context.Background(), domain.EcoNpm, "", "1.0.0"); err == nil {
		t.Error("empty name should error")
	}
	if _, err := f.Fetch(context.Background(), domain.EcoNpm, "p", ""); err == nil {
		t.Error("empty version should error")
	}
}

func TestEscapeName_NonScopedUnchanged(t *testing.T) {
	for _, name := range []string{"lodash", "react", "what.you.like"} {
		if got := escapeName(name); got != name {
			t.Errorf("escapeName(%q) = %q, want unchanged", name, got)
		}
	}
}

func TestEscapeName_ScopedReplaced(t *testing.T) {
	got := escapeName("@scope/pkg")
	if got != "@scope%2fpkg" {
		t.Errorf("escapeName(@scope/pkg) = %q, want @scope%%2fpkg", got)
	}
}

func TestEscapeName_ScopeOnlyNoSlash(t *testing.T) {
	got := escapeName("@scope-only")
	if got != "@scope-only" {
		t.Errorf("escapeName on malformed scope: got %q", got)
	}
}
