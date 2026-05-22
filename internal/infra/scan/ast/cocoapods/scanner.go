// Package cocoapods implements ast.LanguageScanner for CocoaPods
// .podspec files. Podspecs are Ruby DSL evaluated at `pod install`
// time, so a malicious podspec can run arbitrary code on dev machines
// and CI. Uses tree-sitter-ruby with podspec-tuned queries.
//
// Coverage:
//
//   - shell-spawn    s.prepare_command, s.script_phase, system/exec/spawn,
//     IO.popen, Open3.*, backticks, %x{...}
//   - dynamic-eval   eval / instance_eval / class_eval / send
//   - base64-decode  Base64.{decode64,urlsafe_decode64,strict_decode64}
//   - net-egress     Net::HTTP, URI.open/read, open-uri, raw sockets
//   - env-read       ENV['NAME'], ENV.fetch('NAME')
//   - fs-write       File.open with 'w'/'a', File.write, FileUtils.*
//   - raw-ip-literal http(s)://NNN.NNN.NNN.NNN string literals
package cocoapods

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"

	ts "github.com/tree-sitter/go-tree-sitter"
	tsruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the CocoaPods podspec analyzer.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	captureToCap map[uint]domain.Capability

	cursors sync.Pool
}

// New compiles the language and queries.
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tsruby.Language())
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
