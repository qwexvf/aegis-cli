package gleamscan_test

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/gleamscan"
)

func newScanner(t *testing.T) *gleamscan.Scanner {
	t.Helper()
	s, err := gleamscan.New()
	if err != nil {
		t.Fatalf("gleamscan.New: %v", err)
	}
	return s
}

func caps(t *testing.T, src string) map[domain.Capability]struct{} {
	t.Helper()
	s := newScanner(t)
	f := &ast.Findings{Capabilities: map[domain.Capability]struct{}{}}
	s.AnalyzeFile("test.gleam", []byte(src), f)
	return f.Capabilities
}

func hasCap(t *testing.T, src string, want domain.Capability) {
	t.Helper()
	if _, ok := caps(t, src)[want]; !ok {
		t.Errorf("expected %s capability, got none", want)
	}
}

func noCap(t *testing.T, src string, unwanted domain.Capability) {
	t.Helper()
	if _, ok := caps(t, src)[unwanted]; ok {
		t.Errorf("unexpected %s capability", unwanted)
	}
}

func TestNew_NoError(t *testing.T) {
	newScanner(t) // query compilation must not fail
}

func TestDynamicEval_ExternalAttribute(t *testing.T) {
	hasCap(t, `
@external(erlang, "os", "cmd")
pub fn run_cmd(cmd: String) -> String
`, domain.CapDynamicEval)
}

func TestDynamicEval_ExternalFunction(t *testing.T) {
	hasCap(t, `
pub external fn run_cmd(cmd: String) -> String =
  "os" "cmd"
`, domain.CapDynamicEval)
}

func TestNetEgress_Http(t *testing.T) {
	hasCap(t, `import gleam/http`, domain.CapNetEgress)
}

func TestNetEgress_Httpc(t *testing.T) {
	hasCap(t, `import gleam/httpc`, domain.CapNetEgress)
}

func TestNetEgress_ErlangPort(t *testing.T) {
	hasCap(t, `import gleam_erlang/port`, domain.CapNetEgress)
}

func TestEnvRead_ErlangOs(t *testing.T) {
	hasCap(t, `import gleam_erlang/os`, domain.CapEnvRead)
}

func TestFSWrite_Simplifile(t *testing.T) {
	hasCap(t, `import simplifile`, domain.CapFSWriteOutsideRoot)
}

func TestShellSpawn_ErlangAtom(t *testing.T) {
	hasCap(t, `import gleam_erlang/atom`, domain.CapShellSpawn)
}

func TestRawIPLiteral_Match(t *testing.T) {
	hasCap(t, `const c2 = "http://192.168.1.1/beacon"`, domain.CapRawIPLiteral)
}

func TestRawIPLiteral_NoMatch_Domain(t *testing.T) {
	noCap(t, `const url = "https://example.com/api"`, domain.CapRawIPLiteral)
}

func TestCleanFile_NoCaps(t *testing.T) {
	got := caps(t, `
import gleam/io

pub fn main() {
  io.println("hello")
}
`)
	if len(got) != 0 {
		t.Errorf("expected no capabilities for clean file, got %v", got)
	}
}
