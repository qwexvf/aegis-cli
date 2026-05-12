package ghactions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// githubAPIBase is a var (not const) so tests can override it with httptest.Server URL.
var githubAPIBase = "https://api.github.com"

// githubContentEntry is one item from the GitHub Contents API list response.
type githubContentEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	DownloadURL string `json:"download_url"`
	Type        string `json:"type"` // "file" or "dir"
}

// githubFileContent is the response from a single-file GitHub Contents call.
type githubFileContent struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Content  string `json:"content"`  // base64-encoded when Encoding=="base64"
	Encoding string `json:"encoding"` // "base64"
}

// FetchRemoteWorkflows downloads and parses workflow files from a GitHub
// repository via the Contents API. Returns parsed Workflow values ready
// for Analyze(). owner and repo must be non-empty; token is optional
// (without a token the API allows 60 req/hour).
func FetchRemoteWorkflows(ctx context.Context, owner, repo, token string, httpClient *http.Client) ([]ParsedWorkflow, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	dir := fmt.Sprintf("%s/repos/%s/%s/contents/.github/workflows", githubAPIBase, owner, repo)
	var entries []githubContentEntry
	if err := githubGet(ctx, httpClient, token, dir, &entries); err != nil {
		return nil, fmt.Errorf("list workflows %s/%s: %w", owner, repo, err)
	}

	var workflows []ParsedWorkflow
	var parseErrs []string
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		name := strings.ToLower(e.Name)
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		fileURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s", githubAPIBase, owner, repo, e.Path)
		var content githubFileContent
		if err := githubGet(ctx, httpClient, token, fileURL, &content); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", e.Path, err)
		}
		yamlBytes, err := decodeContent(content)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", e.Path, err))
			continue
		}
		wfPath := fmt.Sprintf(".github/workflows/%s", e.Name)
		wf, err := ParseBytes(wfPath, yamlBytes)
		if err != nil {
			// Malformed YAML: skip and keep going so one bad file
			// doesn't abort the whole scan.
			parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", e.Path, err))
			continue
		}
		workflows = append(workflows, ParsedWorkflow{Workflow: wf, Raw: yamlBytes})
	}
	if len(parseErrs) > 0 && len(workflows) == 0 {
		return nil, fmt.Errorf("all workflows failed to parse: %s", strings.Join(parseErrs, "; "))
	}
	return workflows, nil
}

// ParsedWorkflow pairs a parsed Workflow with its raw YAML bytes.
type ParsedWorkflow struct {
	Workflow domain.Workflow
	Raw      []byte
}

func githubGet(ctx context.Context, client *http.Client, token, url string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusNotFound:
		return fmt.Errorf("not found (404) — check repo name and that .github/workflows/ exists")
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("authentication failed (%d) — provide a valid token via --token or $GITHUB_TOKEN", resp.StatusCode)
	case http.StatusTooManyRequests:
		retry := resp.Header.Get("Retry-After")
		if retry != "" {
			return fmt.Errorf("rate limited (429) — retry after %s seconds; use --token for higher limits", retry)
		}
		return fmt.Errorf("rate limited (429) — use --token for higher rate limits (60 → 5000 req/hour)")
	default:
		return fmt.Errorf("unexpected HTTP %d from GitHub API", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func decodeContent(c githubFileContent) ([]byte, error) {
	if c.Encoding != "base64" {
		return nil, fmt.Errorf("unsupported encoding %q", c.Encoding)
	}
	// GitHub wraps base64 in newlines; strip them.
	cleaned := strings.ReplaceAll(c.Content, "\n", "")
	return base64.StdEncoding.DecodeString(cleaned)
}
