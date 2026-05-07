// Package jspkgsource fetches npm package tarballs from the public
// registry (or a configured one), gunzips and untars them in memory,
// and returns the resulting file map plus the package.json manifest
// raw bytes.
//
// Implementation notes:
//   - Works for any npm-registry-compatible source (npmjs, GitHub
//     Packages, JFrog Artifactory, ...) as long as the metadata JSON
//     exposes the standard `versions[v].dist.tarball` URL.
//   - Caches per (name, version) under <cache>/sources/npm/<name>/<v>/
//     so re-runs don't re-download or re-extract.
//   - Files larger than maxFileBytes (1 MiB) are skipped to avoid
//     pathological tarballs (the AST scanner doesn't benefit from
//     minified mega-bundles anyway).
package jspkgsource

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// DefaultRegistryURL is the public npm registry. Override via
// AEGIS_NPM_REGISTRY at the composition root.
const DefaultRegistryURL = "https://registry.npmjs.org"

// Default file size cap. Files larger than this are skipped during
// extraction. Configurable via SetMaxFileBytes.
const defaultMaxFileBytes = 1 * 1024 * 1024

// Fetcher implements usecase.PackageSourceFetcher. Construct via New.
type Fetcher struct {
	registryURL  string
	http         *http.Client
	cacheDir     string
	maxFileBytes int64
	retry        httpx.RetryPolicy
	allowedHosts map[string]struct{} // tarball SSRF allowlist (lowercased)
}

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithRegistryURL overrides the npm registry URL.
func WithRegistryURL(u string) Option {
	return func(f *Fetcher) { f.registryURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient injects a custom HTTP client (tests).
func WithHTTPClient(c *http.Client) Option {
	return func(f *Fetcher) { f.http = c }
}

// WithCacheDir overrides the on-disk cache root.
func WithCacheDir(dir string) Option {
	return func(f *Fetcher) { f.cacheDir = dir }
}

// WithMaxFileBytes sets the per-file size cap (0 disables).
func WithMaxFileBytes(n int64) Option {
	return func(f *Fetcher) { f.maxFileBytes = n }
}

// WithRetryPolicy overrides the retry policy used by metadata and
// tarball requests. Default: httpx.DefaultRetry.
func WithRetryPolicy(p httpx.RetryPolicy) Option {
	return func(f *Fetcher) { f.retry = p }
}

// New builds a Fetcher with sensible defaults: public npm registry,
// 60s HTTP timeout (tarballs can be hundreds of KB), ~/.aegis/cache/sources
// cache dir.
func New(opts ...Option) *Fetcher {
	cacheDir := os.Getenv("AEGIS_CACHE_DIR")
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".aegis", "cache")
	}
	f := &Fetcher{
		registryURL:  strings.TrimRight(DefaultRegistryURL, "/"),
		http:         httpx.NewClient(httpx.Config{Timeout: 60 * time.Second}),
		cacheDir:     filepath.Join(cacheDir, "sources"),
		maxFileBytes: defaultMaxFileBytes,
		retry:        httpx.DefaultRetry,
	}
	if v := os.Getenv("AEGIS_NPM_REGISTRY"); v != "" {
		f.registryURL = strings.TrimRight(v, "/")
	}
	for _, opt := range opts {
		opt(f)
	}
	f.allowedHosts = buildAllowedHosts(f.registryURL)
	return f
}

// buildAllowedHosts seeds the tarball SSRF allowlist with the registry
// host plus any operator-supplied hosts from AEGIS_TARBALL_ALLOWED_HOSTS
// (comma-separated). Hosts are stored lowercased without ports.
func buildAllowedHosts(registryURL string) map[string]struct{} {
	out := map[string]struct{}{}
	if u, err := url.Parse(registryURL); err == nil {
		if h := strings.ToLower(u.Hostname()); h != "" {
			out[h] = struct{}{}
		}
	}
	for h := range strings.SplitSeq(os.Getenv("AEGIS_TARBALL_ALLOWED_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

// validateTarballURL enforces a host allowlist + scheme guard for
// tarball downloads. Defends against a compromised or hostile-pointed
// registry returning a `dist.tarball` URL aimed at cloud IMDS, Consul,
// or other internal services on CI runners.
//
// The allowlist is the gate: only the configured registry host (plus
// any AEGIS_TARBALL_ALLOWED_HOSTS) is reachable, so a foreign hostname
// (or IP literal) returned by a hostile registry can't slip past — even
// a 302 to 169.254.169.254 is blocked by the redirect re-validator in
// downloadTarball.
func (f *Fetcher) validateTarballURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tarball URL parse: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("tarball URL scheme %q not allowed", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, errors.New("tarball URL missing host")
	}
	if _, ok := f.allowedHosts[host]; !ok {
		return nil, fmt.Errorf("tarball host %q not in registry allowlist", host)
	}
	return u, nil
}

// Fetch implements usecase.PackageSourceFetcher.
func (f *Fetcher) Fetch(ctx context.Context, eco domain.Ecosystem, name, version string) (usecase.PackageSource, error) {
	if eco != domain.EcoNpm {
		return usecase.PackageSource{}, fmt.Errorf("jspkgsource: cannot fetch ecosystem %q", eco)
	}
	if name == "" || version == "" {
		return usecase.PackageSource{}, errors.New("jspkgsource: name and version required")
	}

	// 1. Cache hit?
	if src, ok, err := f.loadCached(ctx, name, version); err == nil && ok {
		return src, nil
	}

	// 2. Fetch metadata to get tarball URL + integrity.
	tarballURL, err := f.tarballURL(ctx, name, version)
	if err != nil {
		return usecase.PackageSource{}, err
	}

	// 3. Download tarball.
	body, err := f.downloadTarball(ctx, tarballURL)
	if err != nil {
		return usecase.PackageSource{}, err
	}

	// 4. Extract in memory.
	src, err := extractTarball(body, f.maxFileBytes)
	if err != nil {
		return usecase.PackageSource{}, fmt.Errorf("extract %s@%s: %w", name, version, err)
	}
	// Hash before caching so saveCache can persist it for warm reloads.
	sum := sha256.Sum256(body)
	src.TarballSha256 = hex.EncodeToString(sum[:])

	// 5. Best-effort persist to cache.
	_ = f.saveCache(name, version, src)

	return src, nil
}

// tarballURL fetches package metadata and pulls out the tarball URL
// for the requested version.
func (f *Fetcher) tarballURL(ctx context.Context, name, version string) (string, error) {
	url := f.registryURL + "/" + escapeName(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// abbreviated metadata is enough for tarball URLs
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	resp, err := httpx.Do(ctx, f.http, req, f.retry)
	if err != nil {
		return "", fmt.Errorf("metadata GET %s: %w", redactURL(url), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata %s: HTTP %d", redactURL(url), resp.StatusCode)
	}
	var meta struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxJSONResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read metadata %s: %w", redactURL(url), err)
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("decode metadata: %w", err)
	}
	v, ok := meta.Versions[version]
	if !ok || v.Dist.Tarball == "" {
		return "", fmt.Errorf("version %s of %s not found in registry", version, name)
	}
	return v.Dist.Tarball, nil
}

// downloadTarball returns the raw bytes of a .tgz. Bounded by
// httpx.MaxTarballBytes so a hostile or compromised registry can't
// OOM the CLI by serving a multi-GB response. Real npm tarballs are
// <100MB; the cap is generous headroom.
//
// Re-validates the URL on every redirect hop so a registry that
// 302s to an internal address still gets blocked.
func (f *Fetcher) downloadTarball(ctx context.Context, rawURL string) ([]byte, error) {
	if _, err := f.validateTarballURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// Per-call client copy: same transport, same headers — but with a
	// CheckRedirect that re-runs the SSRF guard. Mutating f.http would
	// affect every other caller of the shared client.
	client := *f.http
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("tarball: too many redirects")
		}
		if _, err := f.validateTarballURL(req.URL.String()); err != nil {
			return err
		}
		return nil
	}
	resp, err := httpx.Do(ctx, &client, req, f.retry)
	if err != nil {
		return nil, fmt.Errorf("tarball GET %s: %w", redactURL(rawURL), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball %s: HTTP %d", redactURL(rawURL), resp.StatusCode)
	}
	body, err := httpx.ReadCapped(resp.Body, httpx.MaxTarballBytes)
	if err != nil {
		return nil, fmt.Errorf("tarball %s: %w", redactURL(rawURL), err)
	}
	return body, nil
}

// redactURL strips path/query so logs don't leak the full URL — only
// the scheme + host survive. Used in error messages so a misconfigured
// registry or a hostile redirect target doesn't end up verbatim in CI
// logs.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "(redacted)"
	}
	return u.Scheme + "://" + u.Host
}

// escapeName URL-escapes scoped package names: `@scope/name` becomes
// `@scope%2fname` per npm registry convention.
func escapeName(name string) string {
	if !strings.HasPrefix(name, "@") {
		return name
	}
	if idx := strings.Index(name, "/"); idx > 0 {
		return name[:idx] + "%2f" + name[idx+1:]
	}
	return name
}

// extractTarball gunzips and untars a tarball into a usecase.PackageSource.
// All npm tarballs use a top-level "package/" directory which we strip.
func extractTarball(raw []byte, maxFileBytes int64) (usecase.PackageSource, error) {
	gz, err := gzip.NewReader(bytesReader(raw))
	if err != nil {
		return usecase.PackageSource{}, fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	out := usecase.PackageSource{Files: map[string][]byte{}}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return usecase.PackageSource{}, fmt.Errorf("tar next: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if maxFileBytes > 0 && hdr.Size > maxFileBytes {
			continue
		}
		// Strip leading "package/" prefix that npm always uses.
		path := strings.TrimPrefix(hdr.Name, "package/")
		if path == hdr.Name {
			// some non-standard tarballs use a different prefix; strip
			// the first component as a fallback so paths are uniform.
			if idx := strings.Index(path, "/"); idx >= 0 {
				path = path[idx+1:]
			}
		}
		// Defense in depth: reject anything the on-disk save would
		// reject anyway, so the in-memory map can't carry traversal
		// keys (`..`, `/abs`) that downstream consumers might use as
		// paths.
		if !isSafeRel(path) {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil {
			return usecase.PackageSource{}, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		if maxFileBytes > 0 && int64(len(body)) > maxFileBytes {
			continue
		}
		out.Files[path] = body
		if path == "package.json" {
			out.Manifest = body
		}
	}
	return out, nil
}

// bytesReader is a tiny helper to give gzip.NewReader an io.Reader
// from a byte slice without pulling bytes.NewReader into the import
// graph in a way that would conflict with stdlib renames in the
// future. Equivalent to bytes.NewReader.
func bytesReader(b []byte) io.Reader {
	return &byteSliceReader{b: b}
}

type byteSliceReader struct {
	b []byte
	i int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
