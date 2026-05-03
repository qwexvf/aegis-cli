package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseRequirementsTxt(t *testing.T) {
	in := []byte(`# project deps
requests==2.31.0
flask==3.0.0  # web framework

# dev tools
pytest==8.0.0 ; python_version >= "3.8"
black==24.1.0 --hash=sha256:abc123
requests[security]==2.31.0

# unsupported (skipped — no exact pin)
numpy>=1.20.0

-r dev-requirements.txt
-e ./local-pkg
`)

	deps, err := parseRequirementsTxt(in, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := map[string]string{
		"requests": "2.31.0",
		"flask":    "3.0.0",
		"pytest":   "8.0.0",
		"black":    "24.1.0",
	}
	got := map[string]string{}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoPyPI {
			t.Errorf("dep %q ecosystem = %v, want pypi", d.Name, d.Ecosystem)
		}
		// requests appears twice (with + without extras) — same version
		got[d.Name] = d.Version
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("requests %q = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["numpy"]; ok {
		t.Error("numpy>=1.20 should NOT be parsed (no exact pin)")
	}
}

func TestParsePoetryLock(t *testing.T) {
	in := []byte(`# This file is automatically @generated
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "urllib3"
version = "2.0.7"

[[package.source]]
url = "ignored"

[metadata]
lock-version = "2.0"
`)
	deps, err := parsePoetryLock(in, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2", len(deps))
	}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoPyPI {
			t.Errorf("ecosystem = %v, want pypi", d.Ecosystem)
		}
	}
}

func TestParsePipfileLock(t *testing.T) {
	in := []byte(`{
  "default": {
    "requests": {"version": "==2.31.0"},
    "flask": {"version": "==3.0.0"}
  },
  "develop": {
    "pytest": {"version": "==8.0.0"}
  }
}`)
	deps, err := parsePipfileLock(in, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deps, want 3", len(deps))
	}
	versions := map[string]string{}
	for _, d := range deps {
		versions[d.Name] = d.Version
	}
	if versions["requests"] != "2.31.0" {
		t.Errorf("requests = %q", versions["requests"])
	}
	if versions["pytest"] != "8.0.0" {
		t.Errorf("pytest = %q", versions["pytest"])
	}
}
