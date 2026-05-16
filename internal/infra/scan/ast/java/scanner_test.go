package java

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
	s.AnalyzeFile("Test.java", []byte(src), f)
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

// minClass wraps a fragment in a minimum-shape Java class so tree-sitter
// produces a real parse tree. The fragment can be any class body.
func minClass(body string) string {
	return "public class T { void f() { " + body + " } }"
}

func TestJava_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"Runtime.getRuntime().exec",
			minClass(`Runtime.getRuntime().exec("ls -la");`),
		},
		{
			"new ProcessBuilder().start()",
			minClass(`new ProcessBuilder("sh", "-c", "rm -rf /").start();`),
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

func TestJava_DynamicEval(t *testing.T) {
	for _, src := range []string{
		minClass(`Class.forName("com.evil.Loader");`),
		minClass(`getSystemClassLoader().loadClass("X");`),
		minClass(`m.invoke(target, args);`),
		minClass(`engine.eval(remoteScript);`),
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapDynamicEval) {
				t.Errorf("expected CapDynamicEval for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestJava_Base64Decode(t *testing.T) {
	for _, src := range []string{
		minClass(`byte[] b = Base64.getDecoder().decode(s);`),
		minClass(`byte[] b = Base64.getMimeDecoder().decode(s);`),
		minClass(`byte[] b = Base64.getUrlDecoder().decode(s);`),
		minClass(`byte[] b = DatatypeConverter.parseBase64Binary(s);`),
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestJava_NetEgress(t *testing.T) {
	for _, src := range []string{
		minClass(`URLConnection c = new URL("http://x").openConnection();`),
		minClass(`InputStream is = new URL("http://x").openStream();`),
		minClass(`Socket s = new Socket("host", 80);`),
		minClass(`ServerSocket s = new ServerSocket(8080);`),
		minClass(`HttpResponse r = client.send(req, BodyHandlers.ofString());`),
		minClass(`HttpGet req = new HttpGet("http://x");`),
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestJava_EnvRead_CredentialFilter(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"System.getenv literal",
			minClass(`String token = System.getenv("AWS_ACCESS_KEY_ID");`),
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"System.getenv another literal",
			minClass(`String tok = System.getenv("GITHUB_TOKEN");`),
			[]string{"GITHUB_TOKEN"},
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

func TestJava_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		minClass(`FileOutputStream fos = new FileOutputStream("/tmp/x");`),
		minClass(`FileWriter fw = new FileWriter("/tmp/x");`),
		minClass(`PrintWriter pw = new PrintWriter("/tmp/x");`),
		minClass(`Files.write(Paths.get("/tmp/x"), bytes);`),
		minClass(`Files.writeString(Paths.get("/tmp/x"), "y");`),
		minClass(`Files.copy(src, Paths.get("/etc/y"));`),
		minClass(`Files.move(src, Paths.get("/root/y"));`),
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestJava_RawIPLiteral(t *testing.T) {
	src := minClass(`String url = "https://1.2.3.4/payload";`)
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral, got %v", capList(f))
	}
}

func TestJava_NoFalsePositive(t *testing.T) {
	src := `package com.example;

import java.util.HashMap;
import java.util.logging.Logger;

public class Greeter {
    private static final Logger LOG = Logger.getLogger("greeter");
    private final HashMap<String, String> cache = new HashMap<>();

    public String hello(String name) {
        LOG.info("greeting " + name);
        return "hi " + name;
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
