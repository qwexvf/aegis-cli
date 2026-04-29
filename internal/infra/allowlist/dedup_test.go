package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

func TestAddRule_DedupReplacesByKey(t *testing.T) {
	userDir := t.TempDir()
	l := loaderAt(userDir, "")

	original := domain.AllowRule{
		Ecosystem: domain.EcoNpm, Name: "lodash",
		VersionRange: "^4", Capability: domain.CapDynamicEval,
		Reason: "first reason",
	}
	replaced, err := l.AddRule(ScopeUser, original)
	if err != nil {
		t.Fatal(err)
	}
	if replaced {
		t.Error("first AddRule should NOT report replaced=true")
	}

	// Same (eco, name, version, capability) but different Reason
	// — should replace, not duplicate.
	updated := original
	updated.Reason = "second reason"
	replaced, err = l.AddRule(ScopeUser, updated)
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Error("re-adding same key should report replaced=true")
	}

	// LoadRaw should show exactly one user rule with the new reason.
	rules, err := l.LoadRaw()
	if err != nil {
		t.Fatal(err)
	}
	userCount := 0
	for _, r := range rules {
		if r.Source == "user" {
			userCount++
			if r.Reason != "second reason" {
				t.Errorf("expected updated reason, got %q", r.Reason)
			}
		}
	}
	if userCount != 1 {
		t.Errorf("expected 1 user rule after replace, got %d", userCount)
	}
}

func TestAddRule_DifferentVersionDoesNotReplace(t *testing.T) {
	// Same (eco, name, capability) but different VersionRange =
	// different rule. Both should coexist.
	userDir := t.TempDir()
	l := loaderAt(userDir, "")

	r1 := domain.AllowRule{Ecosystem: domain.EcoNpm, Name: "lodash",
		VersionRange: "^4", Capability: domain.CapDynamicEval, Reason: "v4"}
	r2 := domain.AllowRule{Ecosystem: domain.EcoNpm, Name: "lodash",
		VersionRange: "^5", Capability: domain.CapDynamicEval, Reason: "v5"}

	if _, err := l.AddRule(ScopeUser, r1); err != nil {
		t.Fatal(err)
	}
	replaced, err := l.AddRule(ScopeUser, r2)
	if err != nil {
		t.Fatal(err)
	}
	if replaced {
		t.Error("different VersionRange should NOT replace")
	}
	rules, _ := l.LoadRaw()
	userCount := 0
	for _, r := range rules {
		if r.Source == "user" {
			userCount++
		}
	}
	if userCount != 2 {
		t.Errorf("expected 2 user rules, got %d", userCount)
	}
}

func TestVerify_BuiltinAlwaysReportsOK(t *testing.T) {
	l := loaderAt(t.TempDir(), t.TempDir())
	results := l.Verify()
	if len(results) < 1 {
		t.Fatal("expected at least one result")
	}
	if results[0].Source != "builtin" || results[0].Err != nil {
		t.Errorf("builtin result: %+v", results[0])
	}
	if results[0].RuleCount == 0 {
		t.Error("builtin should report > 0 rules")
	}
}

func TestVerify_PerFileResults(t *testing.T) {
	userDir, projectDir := t.TempDir(), t.TempDir()

	// Plant a valid user file and a malformed project file.
	validBody := []byte(`version: 1
rules:
  - {ecosystem: npm, name: foo, capability: shell-spawn, reason: ok}
`)
	malformedBody := []byte(`version: 1
rules:
  - {ecosystem: npm, name: bar, capability: not-a-real-cap, reason: x}
`)

	if err := writeFile(filepath.Join(userDir, UserFileName), validBody); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(projectDir, ProjectFileName), malformedBody); err != nil {
		t.Fatal(err)
	}

	l := loaderAt(userDir, projectDir)
	results := l.Verify()
	if len(results) != 3 {
		t.Fatalf("expected 3 results (builtin/user/project), got %d", len(results))
	}
	// Find by source.
	bySrc := map[string]VerifyResult{}
	for _, r := range results {
		bySrc[r.Source] = r
	}
	if bySrc["user"].Err != nil {
		t.Errorf("valid user file should pass: %v", bySrc["user"].Err)
	}
	if bySrc["user"].RuleCount != 1 {
		t.Errorf("user count = %d, want 1", bySrc["user"].RuleCount)
	}
	if bySrc["project"].Err == nil {
		t.Error("malformed project file should fail")
	}
	if !strings.Contains(bySrc["project"].Err.Error(), "unknown capability") {
		t.Errorf("expected capability error, got %v", bySrc["project"].Err)
	}
}

// writeFile is a small test helper that wraps os.WriteFile with our
// canonical 0o600 mode.
func writeFile(path string, body []byte) error {
	return os.WriteFile(path, body, 0o600)
}
