package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/infra/config"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("no file should return empty config, got error: %v", err)
	}
	if cfg.CI.FailOn != "" || cfg.CI.ScanActions || cfg.Actions.FailOn != "" {
		t.Errorf("empty config should be zero value, got %+v", cfg)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "aegis.yml", `version: 1
ci:
  fail_on: prompt
  scan_actions: true
  sarif: true
  no_enrich: false
actions:
  fail_on: medium
  repo: owner/repo
`)
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CI.FailOn != "prompt" {
		t.Errorf("ci.fail_on: got %q", cfg.CI.FailOn)
	}
	if !cfg.CI.ScanActions {
		t.Error("ci.scan_actions: want true")
	}
	if !cfg.CI.SARIF {
		t.Error("ci.sarif: want true")
	}
	if cfg.Actions.FailOn != "medium" {
		t.Errorf("actions.fail_on: got %q", cfg.Actions.FailOn)
	}
	if cfg.Actions.Repo != "owner/repo" {
		t.Errorf("actions.repo: got %q", cfg.Actions.Repo)
	}
}

func TestLoad_DotAegisYml(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".aegis.yml", "version: 1\nci:\n  fail_on: block\n")
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CI.FailOn != "block" {
		t.Errorf("dot file: got %q", cfg.CI.FailOn)
	}
}

func TestLoad_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "aegis.yml", "version: 99\n")
	_, err := config.Load(dir)
	if err == nil {
		t.Error("want error for unsupported version")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "aegis.yml", ":\tinvalid yaml[\n")
	_, err := config.Load(dir)
	if err == nil {
		t.Error("want error for invalid YAML")
	}
}

func TestLoad_InvalidCIFailOn(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "aegis.yml", "version: 1\nci:\n  fail_on: wrongvalue\n")
	_, err := config.Load(dir)
	if err == nil {
		t.Error("want error for invalid ci.fail_on")
	}
}

func TestLoad_InvalidActionsFailOn(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "aegis.yml", "version: 1\nactions:\n  fail_on: notaseverity\n")
	_, err := config.Load(dir)
	if err == nil {
		t.Error("want error for invalid actions.fail_on")
	}
}

func TestLoad_ValidEnumValues(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "aegis.yml", "version: 1\nci:\n  fail_on: prompt\nactions:\n  fail_on: medium\n")
	_, err := config.Load(dir)
	if err != nil {
		t.Errorf("valid enum values should not error: %v", err)
	}
}

func TestLoad_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	// Only set ci.scan_actions — everything else zero
	write(t, dir, "aegis.yml", "version: 1\nci:\n  scan_actions: true\n")
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CI.ScanActions {
		t.Error("scan_actions: want true")
	}
	if cfg.CI.FailOn != "" {
		t.Errorf("unset fail_on should be empty, got %q", cfg.CI.FailOn)
	}
}
