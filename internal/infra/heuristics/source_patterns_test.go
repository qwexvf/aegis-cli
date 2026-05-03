package heuristics

import (
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestDetectSourcePatterns_Obfuscation(t *testing.T) {
	tests := []struct {
		name    string
		js      string
		wantHas domain.Capability
	}{
		{
			name:    "eval(atob(...))",
			js:      `eval(atob("Y29uc29sZS5sb2coJ3BheWxvYWQnKQ=="))`,
			wantHas: domain.CapObfuscatedPayload,
		},
		{
			name:    "Function(decodeURIComponent(...))",
			js:      `(new Function(decodeURIComponent("..." )))()`,
			wantHas: domain.CapObfuscatedPayload,
		},
		{
			name:    "Function(unescape(...))",
			js:      `Function(unescape("%20"))()`,
			wantHas: domain.CapObfuscatedPayload,
		},
		{
			name:    "eval(Buffer.from(..., 'base64'))",
			js:      `eval(Buffer.from("Y29uc29sZS5sb2coKTs=", 'base64').toString())`,
			wantHas: domain.CapObfuscatedPayload,
		},
		{
			name:    "require(atob(...)) for dynamic require",
			js:      `require(atob("Y2hpbGRfcHJvY2Vzcw=="))`,
			wantHas: domain.CapObfuscatedPayload,
		},
		{
			name:    "plain eval — no decode → not flagged here (AST scanner picks it up)",
			js:      `eval("console.log('hi')")`,
			wantHas: 0,
		},
		{
			name:    "atob alone — not flagged (decoding is benign)",
			js:      `const data = atob(input)`,
			wantHas: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps := DetectSourcePatterns(usecase.PackageSource{
				Files: map[string][]byte{"index.js": []byte(tc.js)},
			})
			has := false
			for _, c := range caps {
				if c == domain.CapObfuscatedPayload {
					has = true
				}
			}
			if (tc.wantHas == domain.CapObfuscatedPayload) != has {
				t.Errorf("CapObfuscatedPayload presence mismatch: got %v, want %v (caps=%v)", has, tc.wantHas != 0, caps)
			}
		})
	}
}

func TestDetectSourcePatterns_SuspiciousURL(t *testing.T) {
	tests := []struct {
		name    string
		js      string
		wantHas bool
	}{
		{
			name:    "Pastebin URL",
			js:      `fetch("https://pastebin.com/raw/abc123")`,
			wantHas: true,
		},
		{
			name:    "Discord webhook",
			js:      `fetch("https://discord.com/api/webhooks/111/abc")`,
			wantHas: true,
		},
		{
			name:    "Telegram bot URL",
			js:      `fetch("https://api.telegram.org/bot12345:abc/sendMessage")`,
			wantHas: true,
		},
		{
			name:    "ngrok tunnel",
			js:      `const u = "http://abc.ngrok.io/exfil"`,
			wantHas: true,
		},
		{
			name:    "transfer.sh exfil",
			js:      `fetch("https://transfer.sh/x/data")`,
			wantHas: true,
		},
		{
			name:    "IDN homoglyph (Punycode)",
			js:      `fetch("https://xn--80ak6aa92e.com/x")`, // looks like apple.com
			wantHas: true,
		},
		{
			name:    "ipinfo (exfiltrates victim IP)",
			js:      `axios.get("https://ipinfo.io/json")`,
			wantHas: true,
		},
		{
			name:    "legitimate URL — no flag",
			js:      `fetch("https://api.github.com/repos/foo/bar")`,
			wantHas: false,
		},
		{
			name:    "no URL — no flag",
			js:      `console.log("hello")`,
			wantHas: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps := DetectSourcePatterns(usecase.PackageSource{
				Files: map[string][]byte{"index.js": []byte(tc.js)},
			})
			has := false
			for _, c := range caps {
				if c == domain.CapSuspiciousURL {
					has = true
				}
			}
			if has != tc.wantHas {
				t.Errorf("CapSuspiciousURL presence: got %v, want %v", has, tc.wantHas)
			}
		})
	}
}

// TestDetectSourcePatterns_OnlyJSFiles ensures we don't false-positive
// on README / changelog content that contains the word "eval" or
// example URLs.
func TestDetectSourcePatterns_OnlyJSFiles(t *testing.T) {
	caps := DetectSourcePatterns(usecase.PackageSource{
		Files: map[string][]byte{
			"README.md":    []byte("Don't use eval(atob(x)). And don't fetch https://pastebin.com."),
			"package.json": []byte("{}"),
		},
	})
	if len(caps) != 0 {
		t.Errorf("README content should NOT trigger source-pattern detectors, got %v", caps)
	}
}

// Sanity: catches the pattern even in minified content (one long line).
func TestDetectSourcePatterns_Minified(t *testing.T) {
	js := strings.Repeat("var x=1;", 1000) + `eval(atob("YWJj"))` + strings.Repeat("var y=2;", 1000)
	caps := DetectSourcePatterns(usecase.PackageSource{
		Files: map[string][]byte{"bundle.min.js": []byte(js)},
	})
	found := false
	for _, c := range caps {
		if c == domain.CapObfuscatedPayload {
			found = true
		}
	}
	if !found {
		t.Error("should still detect eval(atob(...)) inside minified bundle")
	}
}
