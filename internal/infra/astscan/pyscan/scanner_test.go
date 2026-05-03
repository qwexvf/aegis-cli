package pyscan

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"
)

// scan is a tiny test helper: build a fresh scanner, run it against
// the given source bytes, return the accumulated Findings.
func scan(t *testing.T, src string) *astscan.Findings {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := astscan.NewFindings()
	s.AnalyzeFile("test.py", []byte(src), f)
	return f
}

func has(f *astscan.Findings, c domain.Capability) bool {
	for cap := range f.Capabilities {
		if cap == c {
			return true
		}
	}
	return false
}

func TestPython_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"subprocess.run", `import subprocess; subprocess.run(["ls"])`},
		{"subprocess.Popen", `import subprocess; subprocess.Popen(["ls"])`},
		{"subprocess.check_output", `import subprocess; subprocess.check_output(["whoami"])`},
		{"os.system", `import os; os.system("rm -rf /")`},
		{"os.popen", `import os; os.popen("ls")`},
		{"os.execv", `import os; os.execv("/bin/sh", ["sh"])`},
		{"pty.spawn", `import pty; pty.spawn("/bin/sh")`},
		{"bare Popen (destructured import)", `from subprocess import Popen; Popen(["x"])`},
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

func TestPython_DynamicEval(t *testing.T) {
	for _, src := range []string{
		`eval("1+1")`,
		`exec("print('hi')")`,
		`compile("x", "<string>", "exec")`,
		`__import__("os")`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapDynamicEval) {
				t.Errorf("expected CapDynamicEval for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPython_Base64Decode(t *testing.T) {
	for _, src := range []string{
		`import base64; base64.b64decode(x)`,
		`import base64; base64.urlsafe_b64decode(x)`,
		`import binascii; binascii.unhexlify(x)`,
		`import codecs; codecs.decode(x, "base64")`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPython_NetEgress(t *testing.T) {
	for _, src := range []string{
		`import requests; requests.get("https://example.com")`,
		`import requests; requests.post(url, data=d)`,
		`import urllib; urllib.urlopen("https://...")`,
		`import urllib.request; urllib.request.urlopen("https://...")`,
		`import httpx; httpx.get(url)`,
		`import socket; socket.create_connection(("host", 80))`,
		`import http.client; http.client.HTTPSConnection("host")`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPython_EnvRead_CredentialFilter(t *testing.T) {
	// The query records env-var names; the credential-shaped-name
	// filter is applied later by the scoring layer (RiskScore).
	// Here we just check that the env names are extracted.
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"os.environ subscript",
			`import os; tok = os.environ["AWS_ACCESS_KEY_ID"]`,
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"os.environ.get",
			`import os; tok = os.environ.get("GITHUB_TOKEN")`,
			[]string{"GITHUB_TOKEN"},
		},
		{
			"os.getenv",
			`import os; tok = os.getenv("DATABASE_URL")`,
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

func TestPython_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		`open("/etc/passwd", "w").write("x")`,
		`open("foo", "a").write("y")`,
		`open("foo", "wb").write(b"z")`,
		`from pathlib import Path; Path("/tmp/x").write_text("y")`,
		`Path("/tmp/x").write_bytes(b"z")`,
		`import shutil; shutil.copy("a", "/etc/b")`,
		`import shutil; shutil.move("a", "/root/b")`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPython_RawIPLiteral(t *testing.T) {
	src := `url = "https://1.2.3.4/payload"`
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral for raw-IP URL, got %v", capList(f))
	}
}

// TestPython_NoFalsePositive verifies common benign code does NOT
// fire any capability. The scanner's role is "interesting", not
// "anything that uses I/O".
func TestPython_NoFalsePositive(t *testing.T) {
	src := `
import json
import logging

def hello(name: str) -> str:
    logging.info("greeting %s", name)
    return json.dumps({"greeting": f"hi {name}"})
`
	f := scan(t, src)
	if len(f.Capabilities) != 0 {
		t.Errorf("benign code triggered capabilities: %v", capList(f))
	}
}

// helpers — turn the map keys into a stable []string for clearer
// failure output.
func capList(f *astscan.Findings) []string {
	out := []string{}
	for c := range f.Capabilities {
		out = append(out, c.String())
	}
	return out
}
func envReads(f *astscan.Findings) []string {
	out := []string{}
	for k := range f.EnvReads {
		out = append(out, k)
	}
	return out
}
