// Package csscan implements astscan.LanguageScanner for C# / .NET
// using tree-sitter with the tree-sitter-c-sharp grammar. Detection
// patterns mirror the other language scanners; see pyscan/queries.scm
// for the design rationale.
//
// Coverage today:
//
//   - shell-spawn         Process.Start, new Process / ProcessStartInfo,
//     *.Start() invocations
//   - dynamic-eval        Activator.CreateInstance,
//     MethodInfo.Invoke (reflection),
//     Assembly.Load / LoadFrom / LoadFile,
//     CSharpScript.EvaluateAsync / RunAsync
//     (Roslyn scripting)
//   - base64-decode       Convert.FromBase64String / FromBase64CharArray /
//     FromHexString
//   - net-egress          HttpClient.{Get,Post,Send,...}Async,
//     new HttpClient / WebClient / HttpRequestMessage,
//     WebRequest.Create / HttpWebRequest.Create,
//     new TcpClient / TcpListener / UdpClient / Socket
//   - env-read            Environment.GetEnvironmentVariable (literal-key)
//   - fs-write-outside-root  File.{WriteAllText,WriteAllBytes,Copy,Move,
//     Create,...}, new StreamWriter / FileStream,
//     Directory.{CreateDirectory,Move,Delete}
//   - raw-ip-literal      http(s)://NNN.NNN.NNN.NNN string literals
package csscan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"

	ts "github.com/tree-sitter/go-tree-sitter"
	tscsharp "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the C# analyzer. Construct via New; the heavy lifting
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
	lang := ts.NewLanguage(tscsharp.Language())
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
