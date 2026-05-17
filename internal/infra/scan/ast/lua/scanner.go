// Package lua implements ast.LanguageScanner for Lua using tree-sitter
// with the tree-sitter-grammars/tree-sitter-lua grammar.
//
// Coverage:
//
//   - shell-spawn        os.execute, io.popen, vim.fn.system,
//     vim.system, vim.fn.jobstart
//   - dynamic-eval       loadstring, load, loadfile, dofile,
//     vim.api.nvim_exec / nvim_exec2
//   - net-egress         require of socket.http, ssl.https,
//     vim.loop.new_tcp, vim.uv.new_tcp
//   - env-read           os.getenv
//   - fs-write-outside-root  io.open with write modes, vim.fn.writefile
//   - install-hook-exec  ffi.load, package.cpath mutation
//   - raw-ip-literal     http(s)://NNN.NNN.NNN.NNN string literals
//
// No OSV ecosystem for Neovim plugins exists, so this scanner is the
// primary signal source for Neovim plugin safety. Import-based detection
// is conservative (require ≠ call) but reliable: a plugin that requires
// `socket.http` is overwhelmingly likely to make HTTP calls.
package lua

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/heuristics"

	tslua "github.com/tree-sitter-grammars/tree-sitter-lua/bindings/go"
	ts "github.com/tree-sitter/go-tree-sitter"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the Lua analyzer. Construct via New.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	captureToCap map[uint]domain.Capability
	// buildStringCapture is the index of the @build-string capture used
	// to flag `build = "..."` install hooks in plugin specs. -1 when the
	// query doesn't define it (older queries.scm).
	buildStringCapture int

	cursors sync.Pool
}

// New compiles the language and queries.
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tslua.Language())
	q, qerr := ts.NewQuery(lang, queriesSource)
	if qerr != nil {
		return nil, qerr
	}

	captureToCap := map[uint]domain.Capability{}
	buildStringCapture := -1
	for i, name := range q.CaptureNames() {
		switch {
		case strings.HasPrefix(name, "cap."):
			if c := capabilityFor(name); c != 0 {
				captureToCap[uint(i)] = c
			}
		case name == "build-string":
			buildStringCapture = i
		}
	}

	return &Scanner{
		lang:               lang,
		query:              q,
		captureToCap:       captureToCap,
		buildStringCapture: buildStringCapture,
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
				continue
			}
			// @build-string capture: only emit install-hook-suspicious
			// when the shell snippet matches the existing malware-pattern
			// matcher (same one used for npm scripts + Cargo build.rs).
			// Benign `build = ":TSUpdate"` strings don't trip it.
			if s.buildStringCapture >= 0 && int(cap.Index) == s.buildStringCapture {
				snippet := string(cap.Node.Utf8Text(body))
				if heuristics.ScriptMatchesMalwarePattern(snippet) {
					f.AddCapability(domain.CapInstallHookSuspicious)
					if f.CollectEvidence {
						line := int(cap.Node.StartPosition().Row) + 1
						f.AddEvidence(domain.CapInstallHookSuspicious, path, line, snippet)
					}
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
