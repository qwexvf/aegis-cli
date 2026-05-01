// Package httpx is the shared HTTP plumbing for every outbound call
// the CLI makes (Aegis API, npm registry, tarball downloads). It
// centralizes three concerns the rest of the codebase used to handle
// ad-hoc:
//
//   - **Transport tuning**: connection pooling, idle timeout, dual-stack
//     dialing. Three http.Client instances at default settings each
//     paid the cold-connection cost on every request.
//   - **Headers**: User-Agent and X-Request-ID injection via a round-
//     tripper, so every call (including those made by libraries we
//     don't control) gets correlation headers without per-call code.
//   - **Retry**: see retry.go. Opt-in per request — the default Client
//     is a vanilla http.Client.
package httpx

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// MaxJSONResponseBytes caps decoded HTTP responses (registry packuments,
// API decisions, GHSA pages). Real npm packuments for the largest
// packages are <10MB; 50MB is enough headroom while preventing a
// hostile or misbehaving server from exhausting memory.
const MaxJSONResponseBytes = 50 * 1024 * 1024

// MaxTarballBytes caps tarball downloads. The largest legitimate npm
// tarballs are tens of MB; 200MB is generous while keeping a hostile
// registry from sending GBs to OOM the CLI.
const MaxTarballBytes = 200 * 1024 * 1024

// ErrResponseTooLarge is returned by ReadCapped when the server
// sent (or attempted to send) more bytes than the cap allows. We
// return ErrResponseTooLarge rather than truncated bytes so callers
// can't accidentally process partial payloads as valid responses.
var ErrResponseTooLarge = errors.New("response body exceeds maximum allowed size")

// ReadCapped reads at most n bytes from r and returns
// ErrResponseTooLarge if r had more data. Use this in place of
// io.ReadAll for any body we don't fully control. The +1 sentinel
// is the standard idiom — read one extra byte to detect overflow.
func ReadCapped(r io.Reader, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("ReadCapped: invalid limit %d", n)
	}
	body, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > n {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

// DefaultTimeout is the per-request hard cap on http.Client. Callers
// that need a longer deadline (tarball downloads) should set their own
// via Client.Timeout after construction or use a context deadline.
const DefaultTimeout = 30 * time.Second

// Config captures the knobs that vary between callers. Zero values are
// safe — the constructors fall back to documented defaults.
type Config struct {
	// UserAgent is the value of the User-Agent header on every request.
	// When empty, the round-tripper does not set the header (so
	// callers can override per-request via req.Header.Set).
	UserAgent string

	// RequestID, when non-empty, is sent as X-Request-ID on every
	// request — used to correlate CLI invocations with API logs.
	RequestID string

	// Timeout overrides DefaultTimeout. Set to zero to keep the
	// default, or to a negative value (e.g. -1) to disable the
	// per-request timeout entirely (let the context govern).
	Timeout time.Duration
}

// NewClient returns a tuned *http.Client. Safe for concurrent use.
//
// Tuning:
//   - MaxIdleConns: 100 (vs default 100 — explicit so future Go releases
//     don't surprise us if they change it).
//   - MaxIdleConnsPerHost: 10 (vs default 2 — registries see bursts).
//   - IdleConnTimeout: 90s.
//   - ForceAttemptHTTP2 = true (registries serve HTTP/2; reduces RTT).
func NewClient(cfg Config) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 {
		timeout = 0
	}
	return &http.Client{
		Transport: &headerInjector{
			next:      transport,
			userAgent: cfg.UserAgent,
			requestID: cfg.RequestID,
		},
		Timeout: timeout,
	}
}

// UserAgent builds the standard CLI user-agent string. Centralizing
// the format means version bumps update one place and the API can
// reliably parse out the version.
//
// Format: aegis-cli/<version> (go<runtime>; <GOOS>/<GOARCH>)
func UserAgent(version string) string {
	if version == "" {
		version = "dev"
	}
	return "aegis-cli/" + version + " (" + runtime.Version() +
		"; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}

// headerInjector is a RoundTripper middleware that sets User-Agent
// and X-Request-ID on every outbound request. It does not overwrite
// values the caller has already set — per-request headers win, which
// matters for the npm registry's Accept header.
type headerInjector struct {
	next      http.RoundTripper
	userAgent string
	requestID string
}

func (h *headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", h.userAgent)
	}
	if h.requestID != "" && req.Header.Get("X-Request-ID") == "" {
		req.Header.Set("X-Request-ID", h.requestID)
	}
	return h.next.RoundTrip(req)
}
