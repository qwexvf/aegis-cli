// Package tarballdrift compares a published npm tarball's file list
// against the upstream git tag for the same version. The shape of
// "review-evading payload" — code in the npm tarball that doesn't
// exist in the github repo and isn't in the standard build-output
// whitelist — is the canonical compromise pattern for every npm
// package-publish incident of the last decade. This detector
// surfaces it without running the build.
package tarballdrift

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/qwexvf/aegis-cli/internal/infra/httpx"
)

// DefaultGitHubAPI is the public GitHub REST endpoint.
const DefaultGitHubAPI = "https://api.github.com"

// ErrTreeNotFound — repo / branch / tag wasn't resolvable. Callers
// treat this as "skip the check", not "the package is bad".
var ErrTreeNotFound = errors.New("git tree not found")

// ErrRateLimited — the GitHub anonymous quota (60/hr) is exhausted.
// Callers should skip cleanly and continue with the rest of the scan;
// authenticated requests get 5000/hr via GITHUB_TOKEN.
var ErrRateLimited = errors.New("github rate-limited")

// Client fetches repository trees from GitHub. In-memory cache keyed
// by (owner, repo, ref) lives for the lifetime of the process — one
// snapshot enrich run hits each tag at most once.
type Client struct {
	baseURL string
	token   string // empty = anonymous
	http    *http.Client

	mu    sync.Mutex
	cache map[string]*TreeResponse
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the GitHub API endpoint (for tests / GHE).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithToken sets a personal access token. Lifts anon 60/hr to 5000/hr.
func WithToken(t string) Option {
	return func(c *Client) { c.token = strings.TrimSpace(t) }
}

// WithHTTPClient overrides the underlying HTTP client (tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// New constructs a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultGitHubAPI,
		http:    httpx.NewClient(httpx.Config{Timeout: 15 * time.Second}),
		cache:   make(map[string]*TreeResponse),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// TreeResponse is the subset of the GitHub git/trees response we use.
// Truncated is set by the API when the tree exceeds 100k entries —
// in that case the file list is partial. We surface this so callers
// can downgrade confidence rather than emit a false-positive drift
// signal on the missing tail.
type TreeResponse struct {
	SHA       string     `json:"sha"`
	Truncated bool       `json:"truncated"`
	Tree      []TreeNode `json:"tree"`
}

// TreeNode is one entry in a git tree. We keep Path + Type; SHA and
// Size aren't needed for path-only drift detection.
type TreeNode struct {
	Path string `json:"path"`
	Type string `json:"type"` // "blob" | "tree" | "commit"
}

// Tree fetches the recursive file tree for (owner, repo, ref). The
// ref may be a branch, tag, or commit SHA. Cached in-memory for the
// lifetime of the Client.
//
// Resolves the ref to a commit SHA first (one extra round-trip) so
// that the trees endpoint can return the recursive listing — the
// trees endpoint only accepts tree-SHAs, not refs.
func (c *Client) Tree(ctx context.Context, owner, repo, ref string) (*TreeResponse, error) {
	key := owner + "/" + repo + "@" + ref
	c.mu.Lock()
	if cached, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	// 1. resolve ref -> commit SHA via /repos/{o}/{r}/commits/{ref}
	sha, err := c.resolveCommitSHA(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}

	// 2. fetch recursive tree
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1",
		c.baseURL, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(sha))
	resp, err := c.do(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := classifyStatus(resp); err != nil {
		return nil, err
	}

	var tr TreeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode tree: %w", err)
	}

	c.mu.Lock()
	c.cache[key] = &tr
	c.mu.Unlock()
	return &tr, nil
}

// resolveCommitSHA hits /commits/{ref} which accepts a branch, tag,
// or commit SHA and always returns a commit object with a top-level
// "sha". Returns ErrTreeNotFound for 404 (ref doesn't exist).
func (c *Client) resolveCommitSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
		c.baseURL, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref))
	resp, err := c.do(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := classifyStatus(resp); err != nil {
		return "", err
	}

	var body struct {
		SHA string `json:"sha"`
		// Commit object also has "commit.tree.sha" but we'll just hit
		// the trees endpoint with the commit SHA — GitHub resolves
		// commit -> tree on the trees endpoint side.
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode commit ref: %w", err)
	}
	if body.SHA == "" {
		return "", ErrTreeNotFound
	}
	return body.SHA, nil
}

func (c *Client) do(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "aegis-cli")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.http.Do(req)
}

// classifyStatus maps GitHub HTTP responses to our two sentinels +
// generic error. Drains the response body on error so the connection
// can be reused.
func classifyStatus(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return ErrTreeNotFound
	case http.StatusForbidden, http.StatusTooManyRequests:
		// Anon quota or secondary rate limit. Distinguish via the
		// header GitHub sets when *unauthenticated* quota is dry.
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			_, _ = io.Copy(io.Discard, resp.Body)
			return ErrRateLimited
		}
		fallthrough
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("github api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
