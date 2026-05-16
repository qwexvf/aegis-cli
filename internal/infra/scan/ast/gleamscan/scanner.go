// Package gleamscan implements ast.LanguageScanner for Gleam using
// tree-sitter with the tree-sitter-gleam grammar.
//
// Coverage:
//
//   - dynamic-eval   @external attribute and legacy external fn declarations
//     (both bypass Gleam's type-safety by delegating to Erlang/JS FFI)
//   - net-egress     import of gleam/http, gleam/httpc, gleam_http,
//     gleam_erlang/port
//   - env-read       import of gleam_erlang/os
//   - fs-write       import of gleam_erlang/file, simplifile
//   - shell-spawn    import of gleam_erlang/atom (used to construct OS calls)
//   - raw-ip-literal http(s)://NNN.NNN.NNN.NNN string literals
package gleamscan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"

	tsgleam "github.com/gleam-lang/tree-sitter-gleam/bindings/go"
	ts "github.com/tree-sitter/go-tree-sitter"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the Gleam analyzer. Construct via New.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	captureToCap map[uint]domain.Capability

	cursors sync.Pool
}

// New compiles the language and queries.
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tsgleam.Language())
	q, qerr := ts.NewQuery(lang, queriesSource)
	if qerr != nil {
		return nil, qerr
	}

	captureToCap := map[uint]domain.Capability{}
	for i, name := range q.CaptureNames() {
		if strings.HasPrefix(name, "cap.") {
			if c := capabilityFor(name); c != 0 {
				captureToCap[uint(i)] = c
			}
		}
	}

	return &Scanner{
		lang:         lang,
		query:        q,
		captureToCap: captureToCap,
		cursors: sync.Pool{New: func() any {
			return ts.NewQueryCursor()
		}},
	}, nil
}

// AnalyzeFile satisfies ast.LanguageScanner.
func (s *Scanner) AnalyzeFile(path string, body []byte, f *ast.Findings) {
	parser := ts.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(s.lang)

	tree := parser.Parse(body, nil)
	if tree == nil {
		return
	}
	defer tree.Close()

	cursor := s.cursors.Get().(*ts.QueryCursor)
	defer s.cursors.Put(cursor)

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
			}
		}
	}
}

func capabilityFor(captureName string) domain.Capability {
	suffix := strings.TrimPrefix(captureName, "cap.")
	for _, c := range domain.AllCapabilities() {
		if c.String() == suffix {
			return c
		}
	}
	return 0
}
