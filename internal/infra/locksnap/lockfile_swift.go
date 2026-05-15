package locksnap

import (
	"encoding/json"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseSwiftPackageResolved parses Swift Package Manager's Package.resolved.
// Both v1 and v2 schema versions are supported.
//
// v2 schema (Swift 5.6+):
//
//	{"pins": [{"identity": "name", "kind": "remoteSourceControl",
//	           "location": "https://...", "state": {"version": "1.0.0"}}],
//	 "version": 2}
//
// v1 schema (older):
//
//	{"object": {"pins": [{"package": "name", "repositoryURL": "https://...",
//	                      "state": {"version": "1.0.0"}}]}, "version": 1}
//
// The OSV "SwiftURL" ecosystem uses the repository URL as the package
// identifier, not the human-readable name. We therefore store the URL
// as Name for OSV lookups. The identity/package field is retained in
// a comment for display purposes but is not surfaced here.
//
// Packages pinned only by revision (no semantic version) are included
// with the revision hash as the version so the VCS heuristic can flag
// them as non-registry dependencies.
func parseSwiftPackageResolved(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("Package.resolved: %w", err)
	}

	switch envelope.Version {
	case 2:
		return parseSwiftResolvedV2(raw)
	default:
		// v1 is the fallback for unrecognised versions too.
		return parseSwiftResolvedV1(raw)
	}
}

func parseSwiftResolvedV2(raw []byte) ([]domain.Dependency, error) {
	var doc struct {
		Pins []struct {
			Location string `json:"location"`
			State    struct {
				Version  string `json:"version"`
				Revision string `json:"revision"`
			} `json:"state"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("Package.resolved v2: %w", err)
	}
	out := make([]domain.Dependency, 0, len(doc.Pins))
	for _, pin := range doc.Pins {
		if pin.Location == "" {
			continue
		}
		ver := pin.State.Version
		if ver == "" {
			ver = pin.State.Revision // branch/commit pin — no semver
		}
		if ver == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoSwiftPM,
			Name:      pin.Location, // OSV SwiftURL uses repo URL as identifier
			Version:   ver,
		})
	}
	return out, nil
}

func parseSwiftResolvedV1(raw []byte) ([]domain.Dependency, error) {
	var doc struct {
		Object struct {
			Pins []struct {
				RepositoryURL string `json:"repositoryURL"`
				State         struct {
					Version  string `json:"version"`
					Revision string `json:"revision"`
				} `json:"state"`
			} `json:"pins"`
		} `json:"object"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("Package.resolved v1: %w", err)
	}
	out := make([]domain.Dependency, 0, len(doc.Object.Pins))
	for _, pin := range doc.Object.Pins {
		if pin.RepositoryURL == "" {
			continue
		}
		ver := pin.State.Version
		if ver == "" {
			ver = pin.State.Revision
		}
		if ver == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoSwiftPM,
			Name:      pin.RepositoryURL,
			Version:   ver,
		})
	}
	return out, nil
}
