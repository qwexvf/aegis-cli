package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// loaderAt builds a Loader rooted at the given user dir with no
// project layer (or with one if projectDir is provided).
func loaderAt(userDir, projectDir string) *Loader {
	return &Loader{userDir: userDir, projectDir: projectDir}
}

func TestLoader_LoadEmptyDirsReturnsBuiltinOnly(t *testing.T) {
	l := loaderAt(t.TempDir(), t.TempDir())
	set, err := l.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := len(domain.BuiltinAllowRules())
	if set.Len() != want {
		t.Errorf("Len = %d, want %d (builtin only)", set.Len(), want)
	}
}

func TestLoader_LoadUserFile(t *testing.T) {
	userDir := t.TempDir()
	yamlBody := []byte(`
version: 1
rules:
  - ecosystem: npm
    name: my-tool
    capability: shell-spawn
    reason: "team-approved build helper"
`)
	if err := os.WriteFile(filepath.Join(userDir, UserFileName), yamlBody, 0o600); err != nil {
		t.Fatal(err)
	}
	l := loaderAt(userDir, "")
	set, err := l.Load()
	if err != nil {
		t.Fatal(err)
	}
	ok, rule := set.Suppresses(domain.EcoNpm, "my-tool", "1.0.0", domain.CapShellSpawn)
	if !ok {
		t.Fatal("user rule should match")
	}
	if rule.Source != "user" {
		t.Errorf("rule Source = %q, want user", rule.Source)
	}
}

func TestLoader_LoadProjectFile(t *testing.T) {
	projectDir := t.TempDir()
	body := []byte(`version: 1
rules:
  - ecosystem: npm
    name: project-tool
    reason: "project-wide allow"
`)
	if err := os.WriteFile(filepath.Join(projectDir, ProjectFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	l := loaderAt(t.TempDir(), projectDir)
	set, _ := l.Load()
	ok, rule := set.Suppresses(domain.EcoNpm, "project-tool", "1.0.0", domain.CapDynamicEval)
	if !ok || rule.Source != "project" {
		t.Errorf("expected project rule match, got ok=%v rule=%+v", ok, rule)
	}
}

func TestLoader_LayeredOrder(t *testing.T) {
	userDir, projectDir := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(userDir, UserFileName), []byte(`version: 1
rules:
  - {ecosystem: npm, name: x, reason: from-user}
`), 0o600)
	os.WriteFile(filepath.Join(projectDir, ProjectFileName), []byte(`version: 1
rules:
  - {ecosystem: npm, name: x, reason: from-project}
`), 0o600)

	rules, err := loaderAt(userDir, projectDir).LoadRaw()
	if err != nil {
		t.Fatal(err)
	}
	// Builtin entries first; user "x" before project "x".
	var sources []string
	for _, r := range rules {
		if r.Name == "x" {
			sources = append(sources, r.Source)
		}
	}
	if len(sources) != 2 || sources[0] != "user" || sources[1] != "project" {
		t.Errorf("layer order wrong: %v", sources)
	}
}

func TestLoader_RejectsMalformedYAML(t *testing.T) {
	userDir := t.TempDir()
	os.WriteFile(filepath.Join(userDir, UserFileName), []byte("this: is: invalid: yaml"), 0o600)
	if _, err := loaderAt(userDir, "").Load(); err == nil {
		t.Error("expected error on malformed YAML")
	}
}

func TestLoader_RejectsUnknownCapability(t *testing.T) {
	userDir := t.TempDir()
	body := []byte(`version: 1
rules:
  - {ecosystem: npm, name: x, capability: not-a-real-cap, reason: y}
`)
	os.WriteFile(filepath.Join(userDir, UserFileName), body, 0o600)
	_, err := loaderAt(userDir, "").Load()
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Errorf("expected unknown-capability error, got %v", err)
	}
}

func TestLoader_RejectsUnknownYAMLKey(t *testing.T) {
	userDir := t.TempDir()
	body := []byte(`version: 1
rules:
  - {ecosystem: npm, name: x, severity: critical, reason: y}
`)
	os.WriteFile(filepath.Join(userDir, UserFileName), body, 0o600)
	_, err := loaderAt(userDir, "").Load()
	if err == nil {
		t.Error("expected error for unknown key 'severity'")
	}
}

func TestLoader_RejectsFutureSchemaVersion(t *testing.T) {
	userDir := t.TempDir()
	body := []byte(`version: 99
rules: []
`)
	os.WriteFile(filepath.Join(userDir, UserFileName), body, 0o600)
	if _, err := loaderAt(userDir, "").Load(); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Errorf("expected schema-version error, got %v", err)
	}
}

func TestLoader_AddRuleCreatesFile(t *testing.T) {
	userDir := t.TempDir()
	l := loaderAt(userDir, "")
	r := domain.AllowRule{
		Ecosystem:  domain.EcoNpm,
		Name:       "my-tool",
		Capability: domain.CapShellSpawn,
		Reason:     "ok",
	}
	if _, err := l.AddRule(ScopeUser, r); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(userDir, UserFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "my-tool") || !strings.Contains(string(body), "shell-spawn") {
		t.Errorf("written YAML missing fields:\n%s", body)
	}
}

func TestLoader_AddRulePreservesExisting(t *testing.T) {
	userDir := t.TempDir()
	l := loaderAt(userDir, "")
	l.AddRule(ScopeUser, domain.AllowRule{
		Ecosystem: domain.EcoNpm, Name: "first", Capability: domain.CapShellSpawn, Reason: "1",
	})
	l.AddRule(ScopeUser, domain.AllowRule{
		Ecosystem: domain.EcoNpm, Name: "second", Capability: domain.CapNetEgress, Reason: "2",
	})
	rules, _ := l.LoadRaw()
	names := []string{}
	for _, r := range rules {
		if r.Source == "user" {
			names = append(names, r.Name)
		}
	}
	if len(names) != 2 || names[0] != "first" || names[1] != "second" {
		t.Errorf("AddRule did not preserve order: %v", names)
	}
}

func TestLoader_AddRuleRejectsInvalid(t *testing.T) {
	l := loaderAt(t.TempDir(), "")
	_, err := l.AddRule(ScopeUser, domain.AllowRule{
		Ecosystem: domain.EcoNpm, Name: "x", VersionRange: "not-a-range",
	})
	if err == nil {
		t.Error("expected validation error on bad semver")
	}
}

func TestLoader_AddRuleProjectScopeRequiresDir(t *testing.T) {
	l := loaderAt(t.TempDir(), "") // no project dir
	_, err := l.AddRule(ScopeProject, domain.AllowRule{Ecosystem: domain.EcoNpm, Name: "x"})
	if err == nil {
		t.Error("project scope without dir must error")
	}
}

func TestLoader_RemoveRuleByPredicate(t *testing.T) {
	userDir := t.TempDir()
	l := loaderAt(userDir, "")
	l.AddRule(ScopeUser, domain.AllowRule{Ecosystem: domain.EcoNpm, Name: "keep", Capability: domain.CapShellSpawn, Reason: "1"})
	l.AddRule(ScopeUser, domain.AllowRule{Ecosystem: domain.EcoNpm, Name: "drop", Capability: domain.CapNetEgress, Reason: "2"})

	n, err := l.RemoveRule(ScopeUser, func(r domain.AllowRule) bool {
		return r.Name == "drop"
	})
	if err != nil || n != 1 {
		t.Errorf("remove count = %d, err = %v", n, err)
	}
	rules, _ := l.LoadRaw()
	for _, r := range rules {
		if r.Source == "user" && r.Name == "drop" {
			t.Error("removed rule still present")
		}
	}
}

func TestLoader_RemoveAllRulesDeletesFile(t *testing.T) {
	userDir := t.TempDir()
	l := loaderAt(userDir, "")
	l.AddRule(ScopeUser, domain.AllowRule{Ecosystem: domain.EcoNpm, Name: "x", Capability: domain.CapShellSpawn, Reason: "1"})
	if _, err := os.Stat(filepath.Join(userDir, UserFileName)); err != nil {
		t.Fatal("file should exist after add")
	}
	if _, err := l.RemoveRule(ScopeUser, func(r domain.AllowRule) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(userDir, UserFileName)); !os.IsNotExist(err) {
		t.Error("file should be deleted when last rule removed")
	}
}

func TestLoader_RemoveRuleNoMatchNoOp(t *testing.T) {
	l := loaderAt(t.TempDir(), "")
	n, err := l.RemoveRule(ScopeUser, func(r domain.AllowRule) bool { return true })
	if err != nil || n != 0 {
		t.Errorf("expected (0, nil), got (%d, %v)", n, err)
	}
}

func TestLoader_PathHelpers(t *testing.T) {
	l := loaderAt("/x", "/y")
	if l.UserPath() != filepath.Join("/x", UserFileName) {
		t.Errorf("UserPath = %q", l.UserPath())
	}
	if l.ProjectPath() != filepath.Join("/y", ProjectFileName) {
		t.Errorf("ProjectPath = %q", l.ProjectPath())
	}
	noProj := loaderAt("/x", "")
	if noProj.ProjectPath() != "" {
		t.Errorf("ProjectPath should be empty when no projectDir")
	}
}

func TestLoader_New_ReadsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AEGIS_CONFIG_DIR", dir)
	l := New("/proj")
	if l.UserPath() != filepath.Join(dir, UserFileName) {
		t.Errorf("AEGIS_CONFIG_DIR not honoured: %q", l.UserPath())
	}
}

func TestScope_StringRoundTrip(t *testing.T) {
	for _, s := range []Scope{ScopeUser, ScopeProject} {
		if got, ok := ScopeFromString(s.String()); !ok || got != s {
			t.Errorf("roundtrip %s", s)
		}
	}
	if _, ok := ScopeFromString("nope"); ok {
		t.Error("unknown scope should fail parse")
	}
}
