package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseCocoaPodsLock parses CocoaPods' Podfile.lock. Structure:
//
//	PODS:
//	  - Alamofire (5.8.0)
//	  - AFNetworking (4.0.1):
//	    - AFNetworking/NSURLSession (= 4.0.1)
//
//	DEPENDENCIES:
//	  - Alamofire (~> 5.0)
//
//	SPEC CHECKSUMS:
//	  Alamofire: abc123
//
//	COCOAPODS: 1.15.2
//
// We parse the PODS section which lists every resolved pod at an exact version.
// The DEPENDENCIES section lists only user-declared (direct) pods;
// we cross-reference to flag Direct == true.
var cocoaPodEntry = regexp.MustCompile(`^  - ([\w/.-]+)\s+\(([^)]+)\)`)
var cocoaDepEntry = regexp.MustCompile(`^  - ([\w/.-]+)\s+`)

func parseCocoaPodsLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency

	// Two-pass: first collect direct pod names from DEPENDENCIES,
	// then collect all pods with versions from PODS.
	directNames := make(map[string]bool)

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	section := ""
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		switch trimmed {
		case "PODS:":
			section = "pods"
			continue
		case "DEPENDENCIES:":
			section = "deps"
			continue
		case "SPEC CHECKSUMS:", "EXTERNAL SOURCES:", "CHECKOUT OPTIONS:", "SPEC REPOS:":
			section = ""
			continue
		}

		switch section {
		case "deps":
			// DEPENDENCIES entries: "  - PodName (version constraint)"
			// Extract just the base pod name (before any subspec "/").
			if m := cocoaDepEntry.FindStringSubmatch(line); len(m) == 2 {
				base := strings.SplitN(m[1], "/", 2)[0]
				directNames[base] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("Podfile.lock scan (pass 1): %w", err)
	}

	// Second pass: collect all resolved pods with exact versions.
	sc2 := bufio.NewScanner(bytes.NewReader(raw))
	sc2.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section = ""
	for sc2.Scan() {
		line := sc2.Text()
		trimmed := strings.TrimSpace(line)

		switch trimmed {
		case "PODS:":
			section = "pods"
			continue
		case "DEPENDENCIES:", "SPEC CHECKSUMS:", "EXTERNAL SOURCES:", "CHECKOUT OPTIONS:", "SPEC REPOS:":
			section = ""
			continue
		}

		if section != "pods" {
			continue
		}
		m := cocoaPodEntry.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		podName := m[1]
		version := m[2]

		// Skip subspec entries (e.g. "AFNetworking/NSURLSession") —
		// the parent pod is already listed with the same version.
		if strings.Contains(podName, "/") {
			continue
		}

		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoCocoaPods,
			Name:      podName,
			Version:   version,
			Direct:    directNames[podName],
		})
	}
	if err := sc2.Err(); err != nil {
		return nil, fmt.Errorf("Podfile.lock scan (pass 2): %w", err)
	}
	return out, nil
}
