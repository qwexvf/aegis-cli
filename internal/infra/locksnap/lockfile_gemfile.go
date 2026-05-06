package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseGemfileLock parses Bundler's Gemfile.lock. The format is
// purpose-built (not YAML, not TOML) but stable: the GEM section
// has a `specs:` subsection where each `name (version)` line is one
// resolved gem; further-indented lines are that gem's dependencies
// (which we ignore — OSV cares about the resolved version, not the
// declared range).
//
// Example:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actionpack (7.1.2)
//	      actionview (= 7.1.2)
//	      activesupport (= 7.1.2)
//	    activerecord (7.1.2)
//	      activemodel (= 7.1.2)
//
// We extract `actionpack 7.1.2`, `activerecord 7.1.2`, etc.
//
// DEPENDENCIES at the bottom of the file lists user-declared (direct)
// gems by name only. We use that to flag direct deps. The PLATFORMS
// and BUNDLED WITH sections are skipped.
func parseGemfileLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency
	directNames := make(map[string]bool)

	// Two-pass: first read DEPENDENCIES to know what's direct, then
	// collect specs. Scanning twice is cheap on lockfile-sized input.

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inDeps := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "DEPENDENCIES" {
			inDeps = true
			continue
		}
		if !inDeps {
			continue
		}
		if trimmed == "" || !strings.HasPrefix(line, "  ") {
			// DEPENDENCIES section ends at first non-indented or
			// blank line.
			break
		}
		// "  rails (~> 7.1)" or "  rails!" — strip everything from
		// the first space or punctuation.
		name := strings.TrimSpace(trimmed)
		for i, r := range name {
			if r == ' ' || r == '!' || r == '(' {
				name = name[:i]
				break
			}
		}
		if name != "" {
			directNames[name] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("gemfile.lock dependencies scan: %w", err)
	}

	// Second pass: collect GEM specs.
	scanner = bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inGem := false
	inSpecs := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "GEM" {
			inGem = true
			inSpecs = false
			continue
		}
		// New top-level section ends GEM.
		isNewSection := len(line) > 0 && line[0] != ' ' && trimmed != "GEM"
		if inGem && isNewSection {
			inGem = false
			inSpecs = false
			continue
		}
		if !inGem {
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// A spec line is indented exactly 4 spaces ("    name (1.0.0)").
		// Sub-deps are indented 6 — skip those.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		// Parse "name (version)". Pre-release and patchlevel
		// suffixes (e.g. "1.2.3.beta1") are kept verbatim — OSV
		// matches the exact string Bundler emits.
		open := strings.Index(trimmed, "(")
		close := strings.LastIndex(trimmed, ")")
		if open < 0 || close < 0 || close <= open {
			continue
		}
		name := strings.TrimSpace(trimmed[:open])
		version := strings.TrimSpace(trimmed[open+1 : close])
		if name == "" || version == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoRubyGems,
			Name:      name,
			Version:   version,
			Direct:    directNames[name],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("gemfile.lock specs scan: %w", err)
	}
	return out, nil
}
