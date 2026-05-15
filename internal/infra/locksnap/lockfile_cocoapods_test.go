package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseCocoaPodsLock_Basic(t *testing.T) {
	raw := []byte(`PODS:
  - Alamofire (5.8.0)
  - AFNetworking (4.0.1):
    - AFNetworking/NSURLSession (= 4.0.1)
    - AFNetworking/Reachability (= 4.0.1)
  - SDWebImage (5.18.0)

DEPENDENCIES:
  - Alamofire (~> 5.0)
  - AFNetworking (~> 4.0)

SPEC CHECKSUMS:
  Alamofire: abc123
  AFNetworking: def456
  SDWebImage: ghi789

PODFILE CHECKSUM: xyz

COCOAPODS: 1.15.2
`)

	deps, err := parseCocoaPodsLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 top-level pods: Alamofire, AFNetworking, SDWebImage
	// Subspecs (AFNetworking/NSURLSession etc.) should be skipped.
	if len(deps) != 3 {
		t.Fatalf("want 3 deps (no subspecs), got %d: %v", len(deps), deps)
	}

	byName := make(map[string]domain.Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	if d, ok := byName["Alamofire"]; !ok {
		t.Error("missing Alamofire")
	} else {
		if d.Version != "5.8.0" {
			t.Errorf("Alamofire version = %q; want 5.8.0", d.Version)
		}
		if d.Ecosystem != domain.EcoCocoaPods {
			t.Errorf("ecosystem = %v; want cocoapods", d.Ecosystem)
		}
		if !d.Direct {
			t.Error("Alamofire should be direct (in DEPENDENCIES)")
		}
	}

	if d, ok := byName["SDWebImage"]; !ok {
		t.Error("missing SDWebImage")
	} else if d.Direct {
		t.Error("SDWebImage should be transitive (not in DEPENDENCIES)")
	}
}

func TestParseCocoaPodsLock_SkipsSubspecs(t *testing.T) {
	raw := []byte(`PODS:
  - Firebase (10.0.0):
    - Firebase/Core (= 10.0.0)
  - Firebase/Core (10.0.0)

DEPENDENCIES:
  - Firebase (~> 10.0)

COCOAPODS: 1.15.2
`)
	deps, err := parseCocoaPodsLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only Firebase (top-level), not Firebase/Core (subspec).
	if len(deps) != 1 {
		t.Fatalf("want 1 dep (subspec skipped), got %d: %v", len(deps), deps)
	}
	if deps[0].Name != "Firebase" {
		t.Errorf("expected Firebase, got %q", deps[0].Name)
	}
}

func TestParseCocoaPodsLock_Empty(t *testing.T) {
	raw := []byte(`PODS:

DEPENDENCIES:

COCOAPODS: 1.15.2
`)
	deps, err := parseCocoaPodsLock(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("want 0 deps, got %d", len(deps))
	}
}
