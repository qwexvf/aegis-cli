// Package goscan implements astscan.LanguageScanner for Go using
// tree-sitter with the tree-sitter-go grammar. Detection patterns
// mirror the Python and Ruby scanners; see pyscan/queries.scm for
// the design rationale and capabilityFor() for the capture→Capability
// mapping.
//
// Coverage today:
//
//   - shell-spawn         os/exec.{Command,CommandContext,LookPath},
//     syscall.{Exec,ForkExec,StartProcess},
//     os.StartProcess
//   - dynamic-eval        plugin.Open — Go's closest equivalent to
//     eval (runtime .so loading)
//   - base64-decode       base64.*Encoding.{DecodeString,Decode},
//     hex.{DecodeString,Decode}
//   - net-egress          net/http.{Get,Post,PostForm,Head,NewRequest...},
//     net.{Dial,DialTimeout,DialContext,Listen...},
//     tls.{Dial,DialWithDialer}
//   - env-read            os.{Getenv,LookupEnv} (literal-key only)
//   - fs-write-outside-root  os.{WriteFile,Create,OpenFile,Mkdir,
//     MkdirAll,Rename,Symlink,Link},
//     ioutil.WriteFile
//   - raw-ip-literal      http(s)://NNN.NNN.NNN.NNN string literals
package goscan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"

	ts "github.com/tree-sitter/go-tree-sitter"
	tsgo "github.com/tree-sitter/tree-sitter-go/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the Go analyzer. Construct via New; the heavy lifting
// (compiling the language and queries) happens once at startup.
type Scanner struct {
	lang  *ts.Language
	query *ts.Query

	captureToCap      map[uint]domain.Capability
	envReadCaptureIdx int

	cursors sync.Pool
}

// New compiles the language and queries.
func New() (*Scanner, error) {
	lang := ts.NewLanguage(tsgo.Language())
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
func capabilityFor(captureName string) domain.Capability {
	suffix := strings.TrimPrefix(captureName, "cap.")
	for _, c := range domain.AllCapabilities() {
		if c.String() == suffix {
			return c
		}
	}
	return 0
}
