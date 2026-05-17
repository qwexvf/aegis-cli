package cli

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParsePkgSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantEco  domain.Ecosystem
		wantName string
		wantVer  string
		wantErr  bool
	}{
		// Default ecosystem.
		{"lodash@4.17.21", domain.EcoNpm, "lodash", "4.17.21", false},
		{"a@b", domain.EcoNpm, "a", "b", false},

		// Scoped npm packages — last @ is the version separator.
		{"@solana/web3.js@1.95.4", domain.EcoNpm, "@solana/web3.js", "1.95.4", false},
		{"@types/node@20.11.0", domain.EcoNpm, "@types/node", "20.11.0", false},

		// Explicit ecosystem prefix.
		{"npm/event-stream@3.3.6", domain.EcoNpm, "event-stream", "3.3.6", false},
		{"npm/@solana/web3.js@1.95.4", domain.EcoNpm, "@solana/web3.js", "1.95.4", false},

		// Errors.
		{"", "", "", "", true},             // empty
		{"lodash", "", "", "", true},       // no version
		{"@scope/name", "", "", "", true},  // scoped, no version
		{"@scope/name@", "", "", "", true}, // empty version
		{"@1.0.0", "", "", "", true},       // leading @ but no name (LastIndex finds the only @, name="")
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			eco, name, ver, err := parsePkgSpec(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got eco=%q name=%q ver=%q", c.in, eco, name, ver)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eco != c.wantEco || name != c.wantName || ver != c.wantVer {
				t.Errorf("parsePkgSpec(%q) = (%q, %q, %q), want (%q, %q, %q)",
					c.in, eco, name, ver, c.wantEco, c.wantName, c.wantVer)
			}
		})
	}
}

func TestParsePkgSpec_UnknownEcosystemFallsBackToNpmName(t *testing.T) {
	// "rust/serde@1.0.0" — "rust" isn't registered as a known
	// ecosystem yet, so the parser should NOT strip it. Today this
	// means treating "rust/serde" as the package name (which the
	// fetcher will reject downstream as not a valid npm scope).
	// The point of this test: don't silently route to a non-existent
	// ecosystem adapter just because the prefix has a slash.
	eco, name, ver, err := parsePkgSpec("rust/serde@1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eco != domain.EcoNpm {
		t.Errorf("eco = %q, want npm (rust isn't registered)", eco)
	}
	if name != "rust/serde" || ver != "1.0.0" {
		t.Errorf("expected name='rust/serde' ver='1.0.0', got name=%q ver=%q", name, ver)
	}
}

func TestExitCodeError_PreservesUnwrap(t *testing.T) {
	inner := &simpleErr{msg: "boom"}
	ec := &exitCodeError{code: 7, err: inner}
	if ec.Error() != "boom" {
		t.Errorf("Error() = %q, want %q", ec.Error(), "boom")
	}
	if ec.ExitCode() != 7 {
		t.Errorf("ExitCode() = %d, want 7", ec.ExitCode())
	}
	if ec.Unwrap() != inner {
		t.Errorf("Unwrap() did not return inner error")
	}
	if ec.Silent() {
		t.Errorf("Silent() should default to false")
	}
}

func TestExitCodeError_SilentFlagPropagates(t *testing.T) {
	ec := &exitCodeError{code: 1, err: &simpleErr{msg: "verdict block"}, silent: true}
	if !ec.Silent() {
		t.Errorf("Silent() should return true when silent=true")
	}
}

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }

func TestResolveAnalyzeTarget_PkgSpecPath(t *testing.T) {
	localPath := ""
	eco, name, ver, err := resolveAnalyzeTarget("lodash@4.17.21", "", &localPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eco != domain.EcoNpm || name != "lodash" || ver != "4.17.21" {
		t.Errorf("got (%q, %q, %q), want (npm, lodash, 4.17.21)", eco, name, ver)
	}
	if localPath != "" {
		t.Errorf("pkg-spec path must NOT mutate localPath; got %q", localPath)
	}
}

func TestResolveAnalyzeTarget_NeovimDirMode(t *testing.T) {
	localPath := ""
	eco, name, ver, err := resolveAnalyzeTarget("/tmp/my-plugin.nvim", "neovim", &localPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eco != domain.EcoNeovim {
		t.Errorf("eco = %q, want neovim", eco)
	}
	if name != "my-plugin.nvim" {
		t.Errorf("name = %q, want my-plugin.nvim (basename of arg)", name)
	}
	// /tmp/my-plugin.nvim doesn't exist → gitHeadSHA returns "" → fallback "unknown"
	if ver != "unknown" {
		t.Errorf("ver = %q, want unknown (no git repo)", ver)
	}
	if localPath != "/tmp/my-plugin.nvim" {
		t.Errorf("localPath = %q, want /tmp/my-plugin.nvim (dir arg should be copied through)", localPath)
	}
}

func TestResolveAnalyzeTarget_NeovimRespectsExistingLocalFlag(t *testing.T) {
	// When the user passes --local explicitly, the dir arg is still used
	// as the positional but localPath stays as the user set it.
	localPath := "/explicit/path"
	_, _, _, err := resolveAnalyzeTarget("/some/dir", "neovim", &localPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if localPath != "/explicit/path" {
		t.Errorf("explicit --local must NOT be overwritten; got %q", localPath)
	}
}

func TestResolveAnalyzeTarget_UnknownEcosystem(t *testing.T) {
	localPath := ""
	_, _, _, err := resolveAnalyzeTarget("./foo", "bogus", &localPath)
	if err == nil {
		t.Fatal("expected error for unknown ecosystem")
	}
}

func TestResolveAnalyzeTarget_UnsupportedEcosystemForDirMode(t *testing.T) {
	// --ecosystem npm (or any non-neovim) with a directory positional
	// should fail: dir-mode is only implemented for neovim today.
	localPath := ""
	_, _, _, err := resolveAnalyzeTarget("./foo", "npm", &localPath)
	if err == nil {
		t.Fatal("expected error: dir mode not implemented for non-neovim")
	}
}

func TestResolveAnalyzeTarget_EmptyDirArg(t *testing.T) {
	localPath := ""
	_, _, _, err := resolveAnalyzeTarget("/", "neovim", &localPath)
	if err == nil {
		t.Fatal(`expected error: "/" doesn't yield a valid plugin name`)
	}
}
