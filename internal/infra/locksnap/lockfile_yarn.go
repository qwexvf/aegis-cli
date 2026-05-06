package locksnap

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// parseYarnLock parses yarn.lock (classic v1 + berry v2/3/4). Both
// formats use blocks of:
//
//	"name@^1.0.0", "name@^1.2.0":
//	  version "1.2.3"
//	  ...
//
// The header line lists one or more constraint strings, each
// "[name]@[range]"; each block resolves to a single concrete version.
// Berry uses the same shape with extra "resolution:" lines we ignore.
//
// We extract one entry per (name, version) pair; multiple constraints
// resolving to the same version produce one entry.
func parseYarnLock(raw []byte, direct map[string]bool) ([]domain.Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		deps    []domain.Dependency
		seen    = map[string]bool{}
		curName string // first name seen in the current block header
		inBlock bool
	)

	flushBlock := func(version string) {
		if curName == "" || version == "" {
			return
		}
		key := curName + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		deps = append(deps, domain.Dependency{
			Ecosystem: domain.EcoNpm,
			Name:      curName,
			Version:   version,
			Direct:    direct[curName],
		})
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Blank line ends a block.
		if strings.TrimSpace(line) == "" {
			inBlock = false
			curName = ""
			continue
		}
		// Comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Block header: starts at column 0 and ends with ":".
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			header := strings.TrimSuffix(line, ":")
			curName = firstYarnHeaderName(header)
			inBlock = true
			continue
		}

		// Body line: looking for `  version "X.Y.Z"`.
		if !inBlock {
			continue
		}
		l := strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(l, "version "); ok {
			ver := strings.Trim(after, " \"")
			flushBlock(ver)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return deps, nil
}

// firstYarnHeaderName takes a yarn-lock header like
//
//	"lodash@^4.17.0", "lodash@^4.17.21"
//	@types/lodash@npm:^4.14.0
//	foo@workspace:packages/foo
//
// and returns just the package name from the first constraint.
func firstYarnHeaderName(header string) string {
	// Split on commas — first constraint only.
	first := strings.SplitN(header, ",", 2)[0]
	first = strings.TrimSpace(first)
	first = strings.Trim(first, "\"")

	// Strip the range. If the name is scoped, the FIRST '@' is the
	// scope marker; look for the SECOND. Otherwise look for the first.
	if strings.HasPrefix(first, "@") {
		rest := first[1:]
		if before, _, ok := strings.Cut(rest, "@"); ok {
			return "@" + before
		}
		return first
	}
	if idx := strings.Index(first, "@"); idx > 0 {
		return first[:idx]
	}
	return first
}
