package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type pypiParser struct{}

func (p *pypiParser) Ecosystems() []domain.Ecosystem { return []domain.Ecosystem{domain.EcoPyPI} }

func (p *pypiParser) Parse(name string, manifestRaw []byte, src domain.PackageSource) NormalizedPackage {
	pkg := NormalizedPackage{
		Eco:         domain.EcoPyPI,
		Name:        name,
		Files:       src.Files,
		ManifestRaw: manifestRaw,
	}
	for filename, body := range src.Files {
		base := strings.ToLower(path.Base(filename))
		if !isPyPIDepFile(base) {
			continue
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if pypiVCSDepPattern.MatchString(line) {
				pkg.Deps = append(pkg.Deps, Dep{
					Name:   extractPyPIDepName(line),
					Spec:   line,
					Source: DepSourceVCS,
				})
			}
		}
	}
	return pkg
}

// pypiVCSDepPattern matches VCS URL prefixes used in Python dependency specs.
var pypiVCSDepPattern = regexp.MustCompile(`(?i)git\+https?://|git\+ssh://`)

// extractPyPIDepName extracts the package name from a PEP 508 URL dep.
// "foo @ git+https://..." → "foo"; "git+https://..." → "".
func extractPyPIDepName(line string) string {
	if before, _, found := strings.Cut(line, " @ "); found {
		return strings.TrimSpace(before)
	}
	return ""
}

// isPyPIDepFile returns true for filenames that commonly declare Python
// dependencies. Does not scan arbitrary .py files to avoid false positives.
func isPyPIDepFile(base string) bool {
	switch base {
	case "requirements.txt", "setup.cfg", "pyproject.toml", "setup.py":
		return true
	}
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}
