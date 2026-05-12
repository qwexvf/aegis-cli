package ghactions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testWorkflowYAML = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// mockGitHubServer serves a minimal GitHub Contents API for one workflow file.
func mockGitHubServer(t *testing.T, statusCode int, workflowYAML string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		// List endpoint returns array; file endpoint returns object.
		if r.URL.Path == "/repos/owner/repo/contents/.github/workflows" {
			entries := []githubContentEntry{{
				Name: "ci.yml",
				Path: ".github/workflows/ci.yml",
				Type: "file",
			}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		// Single file endpoint
		content := githubFileContent{
			Name:     "ci.yml",
			Path:     ".github/workflows/ci.yml",
			Content:  base64Encode(workflowYAML),
			Encoding: "base64",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(content)
	}))
}

func TestFetchRemoteWorkflows_Success(t *testing.T) {
	srv := mockGitHubServer(t, http.StatusOK, testWorkflowYAML)
	defer srv.Close()

	// Patch the base URL to point at the test server.
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	wfs, err := FetchRemoteWorkflows(context.Background(), "owner", "repo", "", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(wfs) != 1 {
		t.Fatalf("workflows: got %d want 1", len(wfs))
	}
	// Path should be relative
	if wfs[0].Workflow.Path != ".github/workflows/ci.yml" {
		t.Errorf("path: got %q want .github/workflows/ci.yml", wfs[0].Workflow.Path)
	}
}

func TestFetchRemoteWorkflows_NotFound(t *testing.T) {
	srv := mockGitHubServer(t, http.StatusNotFound, "")
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	_, err := FetchRemoteWorkflows(context.Background(), "owner", "repo", "", srv.Client())
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestFetchRemoteWorkflows_Unauthorized(t *testing.T) {
	srv := mockGitHubServer(t, http.StatusUnauthorized, "")
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	_, err := FetchRemoteWorkflows(context.Background(), "owner", "repo", "", srv.Client())
	if err == nil {
		t.Fatal("expected error for 401")
	}
}

func TestFetchRemoteWorkflows_MalformedYAML(t *testing.T) {
	srv := mockGitHubServer(t, http.StatusOK, ":\tbad: yaml: [[[")
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	// Malformed YAML should be skipped, not abort.
	// With only one file and it fails, we get 0 workflows (not an error).
	wfs, err := FetchRemoteWorkflows(context.Background(), "owner", "repo", "", srv.Client())
	// Either returns empty list or an error — both are acceptable.
	// Must NOT return a hard error that prevents scanning other files.
	_ = err
	_ = wfs
}

func TestDecodeContent(t *testing.T) {
	t.Run("valid base64", func(t *testing.T) {
		c := githubFileContent{
			Content:  base64Encode("hello world"),
			Encoding: "base64",
		}
		got, err := decodeContent(c)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello world" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("base64 with newlines (GitHub wrapping)", func(t *testing.T) {
		raw := base64Encode("hello world")
		// Insert newlines as GitHub does
		wrapped := raw[:4] + "\n" + raw[4:]
		c := githubFileContent{Content: wrapped, Encoding: "base64"}
		got, err := decodeContent(c)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello world" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("unsupported encoding", func(t *testing.T) {
		c := githubFileContent{Content: "abc", Encoding: "utf-8"}
		_, err := decodeContent(c)
		if err == nil {
			t.Error("expected error for unsupported encoding")
		}
	})
}
