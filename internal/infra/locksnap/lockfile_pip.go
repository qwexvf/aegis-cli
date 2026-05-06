package locksnap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Python ecosystem covers four common lockfile shapes:
//
//   - poetry.lock        TOML (Poetry)
//   - Pipfile.lock       JSON (pipenv)
//   - uv.lock            TOML (uv — Astral's pip replacement)
//   - requirements.txt   plain text "package==version" lines
//
// All resolve to the same domain.EcoPyPI ecosystem so OSV.dev
// receives the same canonical (name, version) tuples regardless of
// which tool the project uses. Direct vs transitive distinction is
// best-effort — only Poetry / pipenv / uv lockfiles encode it; in
// requirements.txt every entry is treated as direct because the
// file IS the manifest.
//
// We deliberately don't pull in a TOML parser dependency just for
// these two formats — a tiny purpose-built reader handles the
// "[[package]]" / name / version triples that both Poetry and uv
// emit. If Python lockfile authors ever do something exotic with
// nested tables, swap to BurntSushi/toml.

// parsePoetryLock parses a Poetry-generated poetry.lock file. The
// format is a series of `[[package]]` tables, each with `name = "..."`
// and `version = "..."`. We ignore everything else (extras, source,
// description, ...).
func parsePoetryLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	pkgs, err := parseTOMLPackages(raw)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Dependency, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoPyPI,
			Name:      p.Name,
			Version:   p.Version,
			Direct:    false, // Poetry encodes dependency category in
			// metadata not parsed here; treat all as transitive.
			// pyproject.toml would need to be merged separately to
			// know which are user-declared.
		})
	}
	return out, nil
}

// parseUvLock parses uv.lock (uv from Astral). Same `[[package]]`
// shape as poetry.lock — same parser.
func parseUvLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	return parsePoetryLock(raw, nil)
}

// parsePipfileLock parses Pipfile.lock (pipenv). The schema splits
// `default` (production) and `develop` deps into separate top-level
// objects; both produce EcoPyPI dependencies. The exact version sits
// under `version: "==X.Y.Z"` per entry — we strip the leading "==".
func parsePipfileLock(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	type pkgEntry struct {
		Version string `json:"version"`
	}
	type pipfileLock struct {
		Default map[string]pkgEntry `json:"default"`
		Develop map[string]pkgEntry `json:"develop"`
	}
	var lf pipfileLock
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("pipfile.lock decode: %w", err)
	}
	out := make([]domain.Dependency, 0, len(lf.Default)+len(lf.Develop))
	add := func(m map[string]pkgEntry, direct bool) {
		for name, e := range m {
			ver := strings.TrimPrefix(e.Version, "==")
			if ver == "" {
				continue
			}
			out = append(out, domain.Dependency{
				Ecosystem: domain.EcoPyPI,
				Name:      name,
				Version:   ver,
				Direct:    direct,
			})
		}
	}
	add(lf.Default, true) // pipenv puts user-declared in [packages]
	add(lf.Develop, true) // dev deps are also user-declared
	return out, nil
}

// parseRequirementsTxt parses pip's plain "name==version" lockfile
// format. Tolerates comments (#), blank lines, and the `-r other.txt`
// include directive (skipped — caller would need to recurse). Lines
// without an `==` pin are skipped: an unpinned `requests` line means
// "any version" and we have no version to query OSV with.
func parseRequirementsTxt(raw []byte, _ map[string]bool) ([]domain.Dependency, error) {
	out := []domain.Dependency{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// skip include directives, editable installs, options
		if strings.HasPrefix(line, "-") {
			continue
		}
		// Must be pinned with `==`. PEP 440 allows other operators
		// (~=, >=, ...) but those don't give us a single version
		// to look up.
		before, after, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name := strings.TrimSpace(before)
		// trim PEP 508 extras: requests[security]==2.31.0
		if br := strings.Index(name, "["); br >= 0 {
			name = name[:br]
		}
		ver := strings.TrimSpace(after)
		// trim PEP 440 environment markers / hashes:
		// foo==1.0 ; python_version >= "3.8"
		// foo==1.0 --hash=sha256:...
		if sc := strings.IndexAny(ver, " ;"); sc >= 0 {
			ver = strings.TrimSpace(ver[:sc])
		}
		if name == "" || ver == "" {
			continue
		}
		out = append(out, domain.Dependency{
			Ecosystem: domain.EcoPyPI,
			Name:      name,
			Version:   ver,
			Direct:    true, // requirements.txt entries are all user-declared
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("requirements.txt scan: %w", err)
	}
	return out, nil
}

// tomlPackage is the (name, version) pair extracted from a `[[package]]`
// TOML table. Keeps the parser tiny — we don't need the rest.
type tomlPackage struct {
	Name    string
	Version string
}

// parseTOMLPackages scans a TOML document for `[[package]]` tables
// and extracts `name` + `version` from each. Hand-rolled to avoid
// pulling in a full TOML parser for two file formats; this handles
// the subset that Poetry and uv emit (no nested tables inside
// [[package]] beyond what we ignore).
func parseTOMLPackages(raw []byte) ([]tomlPackage, error) {
	var out []tomlPackage
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var cur *tomlPackage
	flush := func() {
		if cur != nil && cur.Name != "" && cur.Version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[package]]" {
			flush()
			cur = &tomlPackage{}
			continue
		}
		// New non-package table ends the current package block.
		if strings.HasPrefix(line, "[") && line != "[[package]]" {
			flush()
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "name") {
			cur.Name = tomlString(line)
		} else if strings.HasPrefix(line, "version") {
			cur.Version = tomlString(line)
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("TOML scan: %w", err)
	}
	return out, nil
}

// tomlString extracts the quoted string value from a `key = "value"`
// line. Handles double-quoted strings only — Poetry/uv don't emit
// the multi-line literal forms for name/version. Returns "" on parse
// failure (caller treats empty as "skip this entry").
func tomlString(line string) string {
	_, after, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	rhs := strings.TrimSpace(after)
	if len(rhs) < 2 || rhs[0] != '"' {
		return ""
	}
	end := strings.LastIndex(rhs, "\"")
	if end <= 0 {
		return ""
	}
	return rhs[1:end]
}
