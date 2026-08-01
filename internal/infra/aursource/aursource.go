// Package aursource fetches the raw build artifacts of an AUR package —
// the PKGBUILD bash script and any .install hook — so the domain
// scanner can inspect them before paru/yay executes them.
//
// It reads from the AUR's public cgit + RPC endpoints (no auth, fully
// offline-skippable) or from a local PKGBUILD path/dir. It is an infra
// adapter: it returns domain.AURPackage and never applies policy.
package aursource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

const defaultBaseURL = "https://aur.archlinux.org"

// Fetcher pulls AUR package sources over HTTP.
type Fetcher struct {
	client  *http.Client
	baseURL string
}

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithHTTPClient sets the shared HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fetcher) { f.client = c } }

// WithBaseURL overrides the AUR base URL (tests point this at httptest).
func WithBaseURL(u string) Option { return func(f *Fetcher) { f.baseURL = strings.TrimRight(u, "/") } }

// New constructs a Fetcher.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{client: http.DefaultClient, baseURL: defaultBaseURL}
	for _, o := range opts {
		o(f)
	}
	return f
}

// rpcResp is the subset of the AUR RPC v5 info response we need.
type rpcResp struct {
	Results []struct {
		Name        string `json:"Name"`
		PackageBase string `json:"PackageBase"`
	} `json:"results"`
}

// Fetch resolves an AUR package name to its PackageBase, then downloads
// the PKGBUILD and (if declared) its .install hook. A package not found
// in the AUR returns an error the caller can treat as "not an AUR pkg"
// (e.g. an official-repo package that pacman handles directly).
func (f *Fetcher) Fetch(ctx context.Context, name string) (domain.AURPackage, error) {
	base, err := f.packageBase(ctx, name)
	if err != nil {
		return domain.AURPackage{}, err
	}

	pkgbuild, err := f.plain(ctx, base, "PKGBUILD")
	if err != nil {
		return domain.AURPackage{}, fmt.Errorf("fetch PKGBUILD for %s: %w", name, err)
	}

	pkg := domain.AURPackage{
		Name:     name,
		PKGBUILD: pkgbuild,
		Upstream: domain.ParseUpstreamURL(pkgbuild),
	}

	// .install hook is referenced by `install=<file>` in the PKGBUILD.
	for _, hookName := range installFiles(pkgbuild) {
		if body, herr := f.plain(ctx, base, hookName); herr == nil {
			pkg.Install = append(pkg.Install, body...)
			pkg.Install = append(pkg.Install, '\n')
		}
	}
	return pkg, nil
}

// packageBase queries the RPC info endpoint. AUR packages share a
// PackageBase that owns the git tree; split packages need it to locate
// the PKGBUILD.
func (f *Fetcher) packageBase(ctx context.Context, name string) (string, error) {
	u := fmt.Sprintf("%s/rpc/v5/info?arg[]=%s", f.baseURL, url.QueryEscape(name))
	body, err := f.get(ctx, u)
	if err != nil {
		return "", err
	}
	var r rpcResp
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("parse AUR rpc: %w", err)
	}
	if len(r.Results) == 0 {
		return "", fmt.Errorf("%q not found in AUR", name)
	}
	if b := r.Results[0].PackageBase; b != "" {
		return b, nil
	}
	return name, nil
}

// plain fetches a file from the package's git tree via cgit plain view.
func (f *Fetcher) plain(ctx context.Context, base, file string) ([]byte, error) {
	u := fmt.Sprintf("%s/cgit/aur.git/plain/%s?h=%s",
		f.baseURL, url.PathEscape(file), url.QueryEscape(base))
	return f.get(ctx, u)
}

func (f *Fetcher) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	// Cap the read — a PKGBUILD/.install is never large; protects against
	// a hostile mirror streaming gigabytes.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var reInstall = regexp.MustCompile(`(?m)^\s*install\s*=\s*["']?([^"'\s]+)`)

// installFiles extracts the install= hook filename(s) declared in a
// PKGBUILD. Most packages declare at most one.
func installFiles(pkgbuild []byte) []string {
	var out []string
	for _, m := range reInstall.FindAllSubmatch(pkgbuild, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// ReadLocal builds an AURPackage from a local PKGBUILD file or a
// directory containing one (plus sibling *.install hooks). Used by
// `aegis aur scan ./PKGBUILD` and for offline testing.
func ReadLocal(path string) (domain.AURPackage, error) {
	info, err := os.Stat(path)
	if err != nil {
		return domain.AURPackage{}, err
	}

	dir, pbPath := path, path
	if info.IsDir() {
		pbPath = filepath.Join(path, "PKGBUILD")
	} else {
		dir = filepath.Dir(path)
	}

	pkgbuild, err := os.ReadFile(pbPath)
	if err != nil {
		return domain.AURPackage{}, fmt.Errorf("read PKGBUILD: %w", err)
	}

	pkg := domain.AURPackage{
		Name:     filepath.Base(dir),
		PKGBUILD: pkgbuild,
		Upstream: domain.ParseUpstreamURL(pkgbuild),
	}
	for _, hookName := range installFiles(pkgbuild) {
		if body, herr := os.ReadFile(filepath.Join(dir, hookName)); herr == nil {
			pkg.Install = append(pkg.Install, body...)
			pkg.Install = append(pkg.Install, '\n')
		}
	}
	return pkg, nil
}
