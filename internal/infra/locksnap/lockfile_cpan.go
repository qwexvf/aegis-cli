package locksnap

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseCpanfileSnapshot parses Carton's cpanfile.snapshot. Format:
//
//	DISTRIBUTIONS
//	  M/MI/MIYAGAWA/Module-CPANfile-1.1004.tar.gz
//	    pathname: M/MI/MIYAGAWA/Module-CPANfile-1.1004.tar.gz
//	    provides:
//	      Module::CPANfile 1.1004
//	    requirements:
//	      ...
//
// OSV "CPAN" uses the distribution name (hyphenated, e.g. "Module-CPANfile")
// not the Perl module name (double-colon, e.g. "Module::CPANfile"). We
// extract both name and version from the tarball filename in the `pathname:`
// line, which is the most reliable source.
//
// Pattern: AuthorDir/Name-Version.tar.gz
// The last hyphen before a digit separates the distribution name from version.
var cpanPathnamePattern = regexp.MustCompile(`pathname:\s+(?:[^/]+/)*([A-Za-z][A-Za-z0-9._-]*)-(\d[^/]*?)\.tar\.gz\s*$`)

func parseCpanfileSnapshot(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	var out []domain.Dependency
	seen := make(map[string]bool)

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "pathname:") {
			continue
		}
		m := cpanPathnamePattern.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		name, ver := m[1], m[2]
		key := name + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoCPAN,
			Name:      name,
			Version:   ver,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cpanfile.snapshot scan: %w", err)
	}
	return out, nil
}
