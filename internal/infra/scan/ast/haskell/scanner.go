// Package haskell implements ast.LanguageScanner for Haskell using
// tree-sitter with the tree-sitter-haskell grammar.
//
// Coverage:
//
//   - shell-spawn    System.Process.{callCommand,callProcess,
//     createProcess,runCommand,runProcess,spawnCommand,spawnProcess,
//     readProcess,readCreateProcess}
//   - dynamic-eval   unsafePerformIO, unsafeCoerce, GHC.Plugins,
//     foreign import (FFI bypasses safety guarantees)
//   - base64-decode  Data.ByteString.Base64.{decode,decodeLenient}
//   - net-egress     Network.HTTP, Network.Wreq, Network.HTTP.Simple,
//     Network.HTTP.Client, Network.Socket, http-conduit
//   - env-read       System.Environment.{getEnv,lookupEnv,getEnvironment}
//   - fs-write       System.IO.{writeFile,appendFile,hPutStr,hPutStrLn},
//     Data.ByteString.{writeFile,appendFile}
//   - raw-ip-literal http(s)://NNN.NNN.NNN.NNN string literals
package haskell

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"

	ts "github.com/tree-sitter/go-tree-sitter"
	tshaskell "github.com/tree-sitter/tree-sitter-haskell/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the Haskell analyzer.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	captureToCap map[uint]domain.Capability

	cursors sync.Pool
}

// New compiles the language and queries.
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tshaskell.Language())
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
