// Package rsscan implements ast.LanguageScanner for Rust using
// tree-sitter with the tree-sitter-rust grammar. Detection patterns
// mirror the Python and Ruby scanners; see pyscan/queries.scm for the
// design rationale and capabilityFor() for the capture→Capability
// mapping.
//
// Coverage today:
//
//   - shell-spawn         std::process::Command::new, tokio process,
//     CommandExt::exec, libc::{execv,execve,system,popen},
//     nix::unistd::exec*
//   - dynamic-eval        libloading::Library::new, libc::{dlopen,dlsym}
//     (Rust's closest equivalent to eval — runtime
//     .so/.dll loading)
//   - base64-decode       base64::decode / decode_config / engine.decode
//   - net-egress          reqwest / ureq / attohttpc / surf / isahc top-level
//     helpers, hyper/reqwest::Client construction,
//     TcpStream::connect (sync + tokio)
//   - env-read            std::env::var, std::env::var_os (literal-key only)
//   - fs-write-outside-root  std::fs::{write,copy,rename,hard_link},
//     File::create
//   - raw-ip-literal      http://NNN.NNN.NNN.NNN string literals
//
// install-hook detection for crates.io is the build.rs path, handled
// in heuristics/install_hook_cargo.go (also covers the Cargo.toml
// declarative side). Source-pattern heuristics (suspicious URL,
// obfuscated payload) are language-agnostic and live in heuristics/.
package rsscan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"

	ts "github.com/tree-sitter/go-tree-sitter"
	tsrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
)

//go:embed queries.scm
var queriesSource string

// Scanner is the Rust analyzer. Construct via New; the heavy lifting
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
	lang := ts.NewLanguage(tsrust.Language())
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
