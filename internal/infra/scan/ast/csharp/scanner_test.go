package csharp

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
	s.AnalyzeFile("Test.cs", []byte(src), f)
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

// minClass wraps a fragment in a minimum-shape C# class so tree-sitter
// produces a real parse tree.
func minClass(body string) string {
	return `using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;

class T {
    void F() {
        ` + body + `
    }
}`
}

func TestCSharp_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"Process.Start", `Process.Start("cmd", "/c whoami");`},
		{"new Process", `var p = new Process();`},
		{"new ProcessStartInfo", `var psi = new ProcessStartInfo("cmd");`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, minClass(tc.src))
			if !has(f, domain.CapShellSpawn) {
				t.Errorf("expected CapShellSpawn for %q, got %v", tc.src, capList(f))
			}
		})
	}
}

func TestCSharp_DynamicEval(t *testing.T) {
	for _, src := range []string{
		`var obj = Activator.CreateInstance(t);`,
		`var asm = Assembly.Load(bytes);`,
		`var asm = Assembly.LoadFrom("/tmp/payload.dll");`,
		`var result = method.Invoke(target, args);`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, minClass(src))
			if !has(f, domain.CapDynamicEval) {
				t.Errorf("expected CapDynamicEval for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestCSharp_Base64Decode(t *testing.T) {
	for _, src := range []string{
		`var bytes = Convert.FromBase64String(s);`,
		`var bytes = Convert.FromHexString(s);`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, minClass(src))
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestCSharp_NetEgress(t *testing.T) {
	for _, src := range []string{
		`var c = new HttpClient();`,
		`var w = new WebClient();`,
		`var resp = await client.GetAsync("http://x");`,
		`var resp = await client.PostAsync("http://x", content);`,
		`var req = WebRequest.Create("http://x");`,
		`var s = new TcpClient("host", 80);`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, minClass(src))
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestCSharp_EnvRead_CredentialFilter(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"Environment.GetEnvironmentVariable literal",
			`var tok = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");`,
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"Environment.GetEnvironmentVariable another literal",
			`var tok = Environment.GetEnvironmentVariable("GITHUB_TOKEN");`,
			[]string{"GITHUB_TOKEN"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, minClass(tc.src))
			for _, want := range tc.want {
				if _, ok := f.EnvReads[want]; !ok {
					t.Errorf("expected env-read %q, got %v", want, envReads(f))
				}
			}
		})
	}
}

func TestCSharp_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		`File.WriteAllText("/tmp/x", "y");`,
		`File.WriteAllBytes("/tmp/x", bytes);`,
		`File.AppendAllText("/tmp/x", "y");`,
		`File.Copy("a", "/etc/b");`,
		`File.Move("a", "/root/b");`,
		`var sw = new StreamWriter("/tmp/x");`,
		`var fs = new FileStream("/tmp/x", FileMode.Create);`,
		`Directory.CreateDirectory("/tmp/x");`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, minClass(src))
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestCSharp_RawIPLiteral(t *testing.T) {
	src := minClass(`var url = "https://1.2.3.4/payload";`)
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral, got %v", capList(f))
	}
}

func TestCSharp_NoFalsePositive(t *testing.T) {
	src := `using System;
using System.Collections.Generic;

namespace Example {
    public class Greeter {
        private readonly Dictionary<string, string> cache = new();

        public string Hello(string name) {
            return $"hi {name}";
        }
    }
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
