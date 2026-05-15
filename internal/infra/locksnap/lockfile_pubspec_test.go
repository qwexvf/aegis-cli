package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParsePubspecLock_BasicHosted(t *testing.T) {
	raw := []byte(`packages:
  collection:
    dependency: transitive
    description:
      name: collection
      sha256: "abc123"
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "def456"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.3"
sdks:
  dart: ">=3.0.0 <4.0.0"
`)

	deps, err := parsePubspecLock(raw, nil)
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

	if d, ok := byName["http"]; !ok {
		t.Error("missing http dep")
	} else {
		if d.Version != "1.2.3" {
			t.Errorf("http version = %q; want 1.2.3", d.Version)
		}
		if d.Ecosystem != domain.EcoPub {
			t.Errorf("http ecosystem = %v; want pub", d.Ecosystem)
		}
		if !d.Direct {
			t.Error("http should be direct dep")
		}
	}

	if d, ok := byName["collection"]; !ok {
		t.Error("missing collection dep")
	} else if d.Direct {
		t.Error("collection should be transitive")
	}
}

func TestParsePubspecLock_SkipsSDK(t *testing.T) {
	raw := []byte(`packages:
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.3"
sdks:
  flutter: ">=3.10.0"
`)

	deps, err := parsePubspecLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// flutter (sdk) must be excluded; http (hosted) included
	if len(deps) != 1 {
		t.Fatalf("want 1 dep (sdk skipped), got %d: %v", len(deps), deps)
	}
	if deps[0].Name != "http" {
		t.Errorf("expected http, got %q", deps[0].Name)
	}
}

func TestParsePubspecLock_SkipsPath(t *testing.T) {
	raw := []byte(`packages:
  my_local:
    dependency: "direct main"
    description:
      path: "../my_local"
      relative: true
    source: path
    version: "0.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
`)

	deps, err := parsePubspecLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("path-sourced dep should be skipped, got %v", deps)
	}
}

func TestParsePubspecLock_VersionQuotesStripped(t *testing.T) {
	raw := []byte(`packages:
  pkg:
    dependency: transitive
    description:
      name: pkg
      url: "https://pub.dev"
    source: hosted
    version: "2.0.0"
sdks:
  dart: ">=3.0.0"
`)

	deps, err := parsePubspecLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("want 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "2.0.0" {
		t.Errorf("version = %q; want 2.0.0 (no quotes)", deps[0].Version)
	}
}

func TestParsePubspecLock_Empty(t *testing.T) {
	deps, err := parsePubspecLock([]byte(`packages:
sdks:
  dart: ">=3.0.0"
`), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("want 0 deps, got %d", len(deps))
	}
}
