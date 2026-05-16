// Package phpscan implements ast.LanguageScanner for PHP using
// tree-sitter with the tree-sitter-php grammar. Detection patterns
// mirror the other language scanners; see pyscan/queries.scm for the
// design rationale.
//
// Coverage today:
//
//   - shell-spawn         exec / shell_exec / system / passthru /
//     popen / proc_open / pcntl_exec / escapeshell*,
//     backtick `cmd`
//   - dynamic-eval        eval / assert (with string) / create_function,
//     call_user_func / call_user_func_array
//   - base64-decode       base64_decode / gzinflate / gzuncompress /
//     gzdecode / str_rot13 / hex2bin / convert_uudecode
//     (the canonical webshell decode chain)
//   - net-egress          file_get_contents("http(s)://..."),
//     fopen / readfile / file with URL arg,
//     curl_init / curl_exec / curl_multi_exec,
//     fsockopen / socket_* / stream_socket_*,
//     $client->{get,post,...}() (Guzzle / Symfony)
//   - env-read            getenv("NAME"), $_ENV / $_SERVER subscript
//     (literal-key only)
//   - fs-write-outside-root  file_put_contents / fwrite / copy / rename /
//     symlink / move_uploaded_file / chmod / mkdir,
//     fopen with 'w' / 'a' mode
//   - raw-ip-literal      http(s)://NNN.NNN.NNN.NNN string literals
package phpscan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"

	ts "github.com/tree-sitter/go-tree-sitter"
	tsphp "github.com/tree-sitter/tree-sitter-php/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the PHP analyzer. Construct via New; the heavy lifting
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
	// tree-sitter-php exposes both PHP and PHP-only-tag languages;
	// LanguagePHP is the standard ".php" file grammar.
	lang := ts.NewLanguage(tsphp.LanguagePHP())
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
