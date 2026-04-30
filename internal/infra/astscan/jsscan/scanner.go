// Package jsscan implements astscan.LanguageScanner for JavaScript /
// TypeScript using tree-sitter with the tree-sitter-javascript
// grammar. Detection patterns are written as tree-sitter S-expression
// queries embedded from queries/js.scm.
//
// Concurrency: a Scanner holds an immutable Query that can be shared
// across goroutines for read. Parsers and QueryCursors are created
// per-call (cheap) but pooled if scanning lots of files in parallel.
package jsscan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/astscan"

	ts "github.com/tree-sitter/go-tree-sitter"
	tsjs "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the JS/TS analyzer. Construct via New; the heavy lifting
// (compiling the language and queries) happens once at startup.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	// captureToCap maps capture index → Capability. Pre-computed so
	// the per-match hot loop avoids string lookups.
	captureToCap map[uint]domain.Capability

	// envReadCaptureIdx is the capture index of @env_var (the actual
	// env-name token). -1 if not present in the query.
	envReadCaptureIdx int

	// pool of QueryCursors for concurrent scanning. Cursors are NOT
	// goroutine-safe individually but cheap to allocate.
	cursors sync.Pool
}

// New compiles the language and queries. Returns an error if the
// embedded query string is malformed (a developer bug — should never
// happen in shipping binaries).
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tsjs.Language())
	q, qerr := ts.NewQuery(lang, queriesSource)
	if qerr != nil {
		return nil, qerr
	}

	captureToCap := map[uint]domain.Capability{}
	envIdx := -1
	for i, name := range q.CaptureNames() {
		idx := uint(i)
		switch {
		case strings.HasPrefix(name, "cap."):
			if c := capabilityFor(name); c != 0 {
				captureToCap[idx] = c
			}
		case name == "env_var":
			envIdx = i
		}
	}

	return &Scanner{
		lang:              lang,
		query:             q,
		captureToCap:      captureToCap,
		envReadCaptureIdx: envIdx,
		cursors: sync.Pool{New: func() any {
			return ts.NewQueryCursor()
		}},
	}, nil
}

// AnalyzeFile satisfies astscan.LanguageScanner.
func (s *Scanner) AnalyzeFile(path string, body []byte, f *astscan.Findings) {
	parser := ts.NewParser()
	defer parser.Close()
	parser.SetLanguage(s.lang)

	tree := parser.Parse(body, nil)
	if tree == nil {
		return
	}
	defer tree.Close()

	cursor := s.cursors.Get().(*ts.QueryCursor)
	defer func() {
		s.cursors.Put(cursor)
	}()

	matches := cursor.Matches(s.query, tree.RootNode(), body)
	for {
		m := matches.Next()
		if m == nil {
			break
		}
		for _, cap := range m.Captures {
			if c, ok := s.captureToCap[uint(cap.Index)]; ok {
				f.AddCapability(c)
				if f.CollectEvidence {
					line := int(cap.Node.StartPosition().Row) + 1
					f.AddEvidence(c, path, line, string(cap.Node.Utf8Text(body)))
				}
				continue
			}
			if int(cap.Index) == s.envReadCaptureIdx {
				name := string(cap.Node.Utf8Text(body))
				f.AddEnvRead(name)
			}
		}
	}
}

// capabilityFor maps a "cap.XXX" capture name to the Capability enum.
// Names match Capability.String() suffixes for readability.
func capabilityFor(captureName string) domain.Capability {
	suffix := strings.TrimPrefix(captureName, "cap.")
	for _, c := range domain.AllCapabilities() {
		if c.String() == suffix {
			return c
		}
	}
	return 0
}
