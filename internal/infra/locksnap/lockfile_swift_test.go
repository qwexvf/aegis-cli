package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

var swiftV2 = []byte(`{
  "pins": [
    {
      "identity": "swift-algorithms",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-algorithms",
      "state": {
        "revision": "f195aa56e71ef45fbe7a85a3bae0e2e44b86a0fd",
        "version": "1.0.0"
      }
    },
    {
      "identity": "unstable-pkg",
      "kind": "remoteSourceControl",
      "location": "https://github.com/example/unstable",
      "state": {
        "revision": "abc123def456abc123def456abc123def456abc1"
      }
    }
  ],
  "version": 2
}`)

var swiftV1 = []byte(`{
  "object": {
    "pins": [
      {
        "package": "swift-algorithms",
        "repositoryURL": "https://github.com/apple/swift-algorithms",
        "state": {
          "branch": null,
          "revision": "f195aa56e71ef45fbe7a85a3bae0e2e44b86a0fd",
          "version": "1.0.0"
        }
      },
      {
        "package": "branch-dep",
        "repositoryURL": "https://github.com/example/branch-dep",
        "state": {
          "branch": "main",
          "revision": "deadbeefdeadbeef",
          "version": null
        }
      }
    ]
  },
  "version": 1
}`)

func TestParseSwiftPackageResolved_V2_Versioned(t *testing.T) {
	deps, err := parseSwiftPackageResolved(swiftV2, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	// Versioned dep uses semantic version.
	d, ok := byName["https://github.com/apple/swift-algorithms"]
	if !ok {
		t.Fatal("missing swift-algorithms dep")
	}
	if d.Version != "1.0.0" {
		t.Errorf("version = %q; want 1.0.0", d.Version)
	}
	if d.Ecosystem != domain.EcoSwiftPM {
		t.Errorf("ecosystem = %v; want swifturl", d.Ecosystem)
	}

	// Revision-only dep uses the commit hash as version.
	d2, ok := byName["https://github.com/example/unstable"]
	if !ok {
		t.Fatal("missing unstable dep")
	}
	if d2.Version != "abc123def456abc123def456abc123def456abc1" {
		t.Errorf("revision dep version = %q; want commit hash", d2.Version)
	}
}

func TestParseSwiftPackageResolved_V1(t *testing.T) {
	deps, err := parseSwiftPackageResolved(swiftV1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	if _, ok := byName["https://github.com/apple/swift-algorithms"]; !ok {
		t.Error("missing swift-algorithms from v1")
	}
	// Branch dep: null version → falls back to revision hash.
	bd, ok := byName["https://github.com/example/branch-dep"]
	if !ok {
		t.Fatal("missing branch-dep from v1")
	}
	if bd.Version != "deadbeefdeadbeef" {
		t.Errorf("branch dep version = %q; want revision hash", bd.Version)
	}
}

func TestParseSwiftPackageResolved_SkipsPinWithNoVersion(t *testing.T) {
	raw := []byte(`{
  "pins": [
    {
      "identity": "bad",
      "kind": "remoteSourceControl",
      "location": "https://github.com/example/bad",
      "state": {}
    }
  ],
  "version": 2
}`)
	deps, err := parseSwiftPackageResolved(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("pin with no version/revision should be skipped, got %v", deps)
	}
}

func TestParseSwiftPackageResolved_InvalidJSON(t *testing.T) {
	_, err := parseSwiftPackageResolved([]byte(`{invalid`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
