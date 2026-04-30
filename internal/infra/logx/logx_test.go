package logx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNew_JSONFormatIncludesInvocationID(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: FormatJSON, InvocationID: "abc123", Out: &buf, Verbose: true})
	l.Info("hello", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %v\noutput: %q", err, buf.String())
	}
	if rec["cli_invocation_id"] != "abc123" {
		t.Errorf("invocation id missing/wrong: %v", rec["cli_invocation_id"])
	}
	if rec["msg"] != "hello" {
		t.Errorf("msg lost: %v", rec)
	}
	if rec["k"] != "v" {
		t.Errorf("attr lost: %v", rec)
	}
}

func TestNew_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: FormatText, Out: &buf, Verbose: true})
	l.Info("hello", "k", "v")

	out := buf.String()
	if !strings.Contains(out, "hello") || !strings.Contains(out, "k=v") {
		t.Errorf("text format unexpected: %q", out)
	}
}

func TestNew_LevelGate(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: FormatText, Out: &buf}) // default WARN
	l.Info("muffled")
	l.Warn("through")
	out := buf.String()
	if strings.Contains(out, "muffled") {
		t.Errorf("Info should be silenced at WARN: %q", out)
	}
	if !strings.Contains(out, "through") {
		t.Errorf("Warn should pass: %q", out)
	}
}

func TestNew_VerboseEnablesDebug(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: FormatText, Out: &buf, Verbose: true})
	l.Debug("verbose-only")
	if !strings.Contains(buf.String(), "verbose-only") {
		t.Errorf("Debug suppressed under Verbose: %q", buf.String())
	}
}

func TestNew_EnvLevelOverride(t *testing.T) {
	t.Setenv("AEGIS_LOG_LEVEL", "debug")
	var buf bytes.Buffer
	l := New(Config{Format: FormatText, Out: &buf})
	l.Debug("env-debug")
	if !strings.Contains(buf.String(), "env-debug") {
		t.Errorf("AEGIS_LOG_LEVEL=debug ignored: %q", buf.String())
	}
}
