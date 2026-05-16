// Package ruby implements ast.LanguageScanner for Ruby using
// tree-sitter with the tree-sitter-ruby grammar. Detection patterns
// mirror the Python scanner; see py/queries.scm for the design
// rationale and capabilityFor() for the capture→Capability mapping.
//
// Coverage today (mirrors py capability set):
//
//   - shell-spawn         system / exec / spawn / fork, IO.popen, Open3.*,
//     PTY.spawn, backticks, %x{...}
//   - dynamic-eval        eval / instance_eval / class_eval / module_eval,
//     send / public_send / __send__
//   - base64-decode       Base64.{decode64,urlsafe_decode64,strict_decode64}
//   - net-egress          Net::HTTP.*, URI.{open,parse,read}, open-uri,
//     HTTParty/RestClient/Faraday/Excon, raw sockets
//   - env-read            ENV['NAME'], ENV.fetch('NAME')
//   - fs-write-outside-root  File.open('w'/'a'), File.write, IO.write,
//     FileUtils.{cp,mv,install,...}
//   - raw-ip-literal      http://NNN.NNN.NNN.NNN string literals
//
// install-hook is detected manifest-side (heuristics package handles
// .gemspec post-install hooks separately if/when those parsers land).
// Source-pattern heuristics (obfuscated payload, suspicious URL) are
// regex-over-source and language-agnostic — they live in heuristics/.
package ruby

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

// Scanner is the Ruby analyzer. Construct via New; the heavy lifting
// (compiling the language and queries) happens once at startup.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	captureToCap      map[uint]domain.Capability
	envReadCaptureIdx int

	cursors sync.Pool
}

// New compiles the language and queries. Returns an error if the
// embedded query string is malformed (a developer bug — should never
// happen in shipping binaries).
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tsruby.Language())
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

// AnalyzeFile satisfies ast.LanguageScanner. Walks the AST of the
// given Ruby source bytes, fires every capability whose query matches,
// and accumulates env-var reads for the credential-name filter applied
// at scoring time.
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
