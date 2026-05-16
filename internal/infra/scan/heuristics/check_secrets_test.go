package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func runSecretsCheck(t *testing.T, files map[string][]byte) []domain.Capability {
	t.Helper()
	return checkSecrets(NormalizedPackage{
		Name:  "test",
		Eco:   domain.EcoNpm,
		Files: files,
	})
}

func TestCheckSecrets_DetectsRealCredentials(t *testing.T) {
	// Each token literal is split across string concatenations so the
	// raw file content never contains a complete pattern that GitHub's
	// push-protection (or any source-side secret scanner) would block.
	tests := []struct {
		name string
		body string
	}{
		{"AWS AKIA access key", `const KEY = "` + "AKIA" + `1234567890ABCDEF";`},
		{"AWS ASIA STS key", `const TMP = "` + "ASIA" + `QWERTYUIOPASDFGH";`},
		{"GitHub PAT (classic)", `token: "` + "g" + "hp_" + `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`},
		{"GitHub fine-grained PAT", `token: "` + "g" + "ithub_pat_" + `1234567890123456789012345678901234567890123456789012345678901234567890123456789012"`},
		{"npm token", `const NPM = "` + "np" + "m_" + `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`},
		{"PEM private key header", "-----" + "BEGIN RSA PRIVATE KEY" + "-----\nMIIEpAI"},
		{"Stripe live secret key", `const k = "` + "sk_" + "live_" + `aaaaaaaaaaaaaaaaaaaaaaaaa";`},
		{"SendGrid API key", `var sg = "` + "S" + "G" + `.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";`},
		{"Twilio account SID", `const ac = "` + "A" + "C" + `0123456789abcdef0123456789abcdef";`},
		{"Slack bot token", `const t = "` + "xo" + "xb" + `-123456789-987654321-abcdefghijklmnop";`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := runSecretsCheck(t, map[string][]byte{
				"src/leak.js": []byte(tt.body),
			})
			if len(caps) == 0 {
				t.Errorf("expected CapHardcodedSecret to fire on %s — body %q", tt.name, tt.body)
			}
		})
	}
}

func TestCheckSecrets_NoFalsePositiveOnLikelyBenign(t *testing.T) {
	// Patterns that look suspicious but aren't real credentials. The
	// scanner must not flag these — false positives would tank trust on
	// legitimate packages.
	tests := []struct {
		name string
		body string
	}{
		// AWS-published canonical examples (excluded via knownPlaceholders)
		{"AWS docs AKIAIOSFODNN7EXAMPLE", `// example: AKIAIOSFODNN7EXAMPLE — replace with real key`},
		{"AWS STS docs ASIAIOSFODNN7EXAMPLE", `const TMP = "ASIAIOSFODNN7EXAMPLE";`},
		{"all-zero AKIA placeholder", `// configure: AKIA0000000000000000`},

		// Common false-positive shapes that should NOT match:
		{"short string with prefix-like substring", `var x = "ghp_short";`},
		{"too-short Stripe-like", `var x = "sk_test_short";`},
		{"random base64 that is not a secret", `const h = "dGVzdHRlc3R0ZXN0dGVzdA==";`},
		{"npm prefix in identifier name", `function npm_install(name) {}`},
		// "Bearer xxx" pattern with short token (< 40 chars) → must not fire
		{"short Bearer header", `headers: { Authorization: "Bearer abc123" }`},
		// gh prefix as part of unrelated identifier
		{"ghost as variable name", `let ghost = true; let pumpkin = false;`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := runSecretsCheck(t, map[string][]byte{
				"src/code.js": []byte(tt.body),
			})
			if len(caps) > 0 {
				t.Errorf("FALSE POSITIVE on %s — body %q produced %v", tt.name, tt.body, caps)
			}
		})
	}
}

func TestCheckSecrets_IgnoresNonSourceFiles(t *testing.T) {
	// README, package.json, license files etc. should not trigger
	// even when they contain credential-shaped strings (e.g. tutorial
	// snippets, example .env in docs).
	body := []byte("AKIA" + `1234567890ABCDEF should not flag this README`)
	caps := runSecretsCheck(t, map[string][]byte{
		"README.md":    body,
		"package.json": body,
		"LICENSE":      body,
		"docs/api.md":  body,
	})
	if len(caps) > 0 {
		t.Errorf("non-source files should be ignored; got %v", caps)
	}
}

func TestCheckSecrets_EmptyPackage(t *testing.T) {
	if caps := runSecretsCheck(t, nil); len(caps) > 0 {
		t.Errorf("empty file map should produce no findings, got %v", caps)
	}
	if caps := runSecretsCheck(t, map[string][]byte{}); len(caps) > 0 {
		t.Errorf("empty file map should produce no findings, got %v", caps)
	}
}

func TestCheckSecrets_TruncatesLargeFiles(t *testing.T) {
	// A secret beyond the 256 KB scan cap should NOT be detected.
	// This is acceptable: scanning past 256 KB on every source file
	// would dominate runtime on large bundles. The secret IS detected
	// at small offsets within the cap.
	bigBody := make([]byte, 300*1024)
	copy(bigBody, []byte("// padding\n"))
	// Stash the secret near the end (past cap)
	copy(bigBody[280*1024:], []byte(`const K = "`+"AKIA"+`1234567890ABCDEF";`))

	caps := runSecretsCheck(t, map[string][]byte{"src/big.js": bigBody})
	if len(caps) > 0 {
		t.Errorf("secret past 256KB scan cap shouldn't fire (perf trade-off); got %v", caps)
	}

	// Same secret at the start should fire.
	smallBody := []byte(`const K = "` + "AKIA" + `1234567890ABCDEF";` + string(make([]byte, 1024)))
	if caps := runSecretsCheck(t, map[string][]byte{"src/small.js": smallBody}); len(caps) == 0 {
		t.Errorf("secret near start should fire even with padding after")
	}
}

func TestCheckSecrets_BearerToken_RequiresMinLength(t *testing.T) {
	// Bearer pattern requires ≥40 char token to reduce FPs. Verify boundary.
	short := `Authorization: Bearer ` + string(repeatByte('a', 30))
	long := `Authorization: Bearer ` + string(repeatByte('a', 50))

	if caps := runSecretsCheck(t, map[string][]byte{"a.js": []byte(short)}); len(caps) > 0 {
		t.Errorf("30-char Bearer token should NOT fire, got %v", caps)
	}
	if caps := runSecretsCheck(t, map[string][]byte{"a.js": []byte(long)}); len(caps) == 0 {
		t.Errorf("50-char Bearer token should fire")
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
