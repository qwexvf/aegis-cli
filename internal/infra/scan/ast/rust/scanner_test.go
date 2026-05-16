package rust

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
)

func scan(t *testing.T, src string) *ast.Findings {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := ast.NewFindings()
	s.AnalyzeFile("test.rs", []byte(src), f)
	return f
}

func has(f *ast.Findings, c domain.Capability) bool {
	for cap := range f.Capabilities {
		if cap == c {
			return true
		}
	}
	return false
}

func TestRust_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"std::process::Command::new",
			`fn main() { std::process::Command::new("ls").status().ok(); }`,
		},
		{
			"Command::new (use)",
			`use std::process::Command;
			 fn main() { Command::new("rm").arg("-rf").arg("/").status().ok(); }`,
		},
		{
			"tokio::process::Command::new",
			`async fn x() { let _ = tokio::process::Command::new("sh").spawn(); }`,
		},
		{
			"libc::system FFI",
			`fn x() { unsafe { libc::system(c"echo hi".as_ptr()) }; }`,
		},
		{
			"libc::execv FFI",
			`fn x() { unsafe { libc::execv(p, av) }; }`,
		},
		{
			"nix::unistd::execv",
			`fn x() { nix::unistd::execv(&p, &args).unwrap(); }`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, tc.src)
			if !has(f, domain.CapShellSpawn) {
				t.Errorf("expected CapShellSpawn for %q, got %v", tc.src, capList(f))
			}
		})
	}
}

func TestRust_DynamicEval(t *testing.T) {
	for _, src := range []string{
		`fn x() { unsafe { libloading::Library::new("/tmp/x.so").unwrap() }; }`,
		`fn x() { unsafe { libloading::os::unix::Library::new(p).unwrap() }; }`,
		`fn x() { unsafe { libc::dlopen(p, 0) }; }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapDynamicEval) {
				t.Errorf("expected CapDynamicEval for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRust_Base64Decode(t *testing.T) {
	for _, src := range []string{
		`fn x(s: &str) { let _ = base64::decode(s); }`,
		`fn x(s: &str) { let _ = base64::decode_config(s, base64::STANDARD); }`,
		`fn x(e: Engine, s: &str) { let _ = e.decode(s); }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRust_NetEgress(t *testing.T) {
	for _, src := range []string{
		`async fn x() { let _ = reqwest::get("http://x").await; }`,
		`async fn x() { let _ = reqwest::Client::new(); }`,
		`fn x() { let _ = ureq::get("http://x").call(); }`,
		`async fn x() { let _ = surf::get("http://x").await; }`,
		`fn x() { let _ = std::net::TcpStream::connect("host:80"); }`,
		`async fn x() { let _ = tokio::net::TcpStream::connect("host:80").await; }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRust_EnvRead_CredentialFilter(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"std::env::var",
			`fn x() { let _ = std::env::var("AWS_ACCESS_KEY_ID"); }`,
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"env::var via use",
			`use std::env; fn x() { let _ = env::var("GITHUB_TOKEN"); }`,
			[]string{"GITHUB_TOKEN"},
		},
		{
			"std::env::var_os",
			`fn x() { let _ = std::env::var_os("DATABASE_URL"); }`,
			[]string{"DATABASE_URL"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, tc.src)
			for _, want := range tc.want {
				if _, ok := f.EnvReads[want]; !ok {
					t.Errorf("expected env-read %q, got %v", want, envReads(f))
				}
			}
		})
	}
}

func TestRust_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		`fn x() { let _ = std::fs::write("/tmp/x", b"y"); }`,
		`fn x() { let _ = std::fs::copy("a", "/etc/b"); }`,
		`fn x() { let _ = std::fs::rename("a", "/root/b"); }`,
		`fn x() { let _ = std::fs::hard_link("a", "/usr/local/b"); }`,
		`use std::fs::File; fn x() { let _ = File::create("/tmp/x"); }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRust_RawIPLiteral(t *testing.T) {
	src := `fn x() { let url = "https://1.2.3.4/payload"; }`
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral for raw-IP URL, got %v", capList(f))
	}
}

// TestRust_NoFalsePositive verifies common benign code does NOT fire
// any capability.
func TestRust_NoFalsePositive(t *testing.T) {
	src := `
use std::collections::HashMap;
use serde::Serialize;

#[derive(Serialize)]
pub struct Greeting {
    msg: String,
}

pub fn hello(name: &str) -> Greeting {
    Greeting { msg: format!("hi {}", name) }
}
`
	f := scan(t, src)
	if len(f.Capabilities) != 0 {
		t.Errorf("benign code triggered capabilities: %v", capList(f))
	}
}

func capList(f *ast.Findings) []string {
	out := []string{}
	for c := range f.Capabilities {
		out = append(out, c.String())
	}
	return out
}

func envReads(f *ast.Findings) []string {
	out := []string{}
	for k := range f.EnvReads {
		out = append(out, k)
	}
	return out
}
