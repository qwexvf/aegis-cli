package goscan

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
	s.AnalyzeFile("test.go", []byte(src), f)
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

const pkgPrefix = "package main\n\n"

func TestGo_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"exec.Command", `import "os/exec"
func x() { _ = exec.Command("ls").Run() }`},
		{"exec.CommandContext", `import (
	"context"
	"os/exec"
)
func x() { _ = exec.CommandContext(context.Background(), "rm", "-rf", "/") }`},
		{"syscall.Exec", `import "syscall"
func x() { _ = syscall.Exec("/bin/sh", nil, nil) }`},
		{"syscall.ForkExec", `import "syscall"
func x() { _, _ = syscall.ForkExec("/bin/sh", nil, nil) }`},
		{"os.StartProcess", `import "os"
func x() { _, _ = os.StartProcess("/bin/sh", nil, nil) }`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, pkgPrefix+tc.src)
			if !has(f, domain.CapShellSpawn) {
				t.Errorf("expected CapShellSpawn for %q, got %v", tc.src, capList(f))
			}
		})
	}
}

func TestGo_DynamicEval(t *testing.T) {
	src := pkgPrefix + `import "plugin"
func x() { _, _ = plugin.Open("/tmp/payload.so") }`
	f := scan(t, src)
	if !has(f, domain.CapDynamicEval) {
		t.Errorf("expected CapDynamicEval (plugin.Open), got %v", capList(f))
	}
}

func TestGo_Base64Decode(t *testing.T) {
	for _, src := range []string{
		`import "encoding/base64"
func x(s string) { _, _ = base64.StdEncoding.DecodeString(s) }`,
		`import "encoding/base64"
func x(s string) { _, _ = base64.RawStdEncoding.DecodeString(s) }`,
		`import "encoding/base64"
func x(s string) { _, _ = base64.URLEncoding.DecodeString(s) }`,
		`import "encoding/hex"
func x(s string) { _, _ = hex.DecodeString(s) }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, pkgPrefix+src)
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestGo_NetEgress(t *testing.T) {
	for _, src := range []string{
		`import "net/http"
func x() { _, _ = http.Get("http://x") }`,
		`import "net/http"
func x() { _, _ = http.Post("http://x", "application/json", nil) }`,
		`import "net/http"
func x() { _, _ = http.NewRequest("GET", "http://x", nil) }`,
		`import "net"
func x() { _, _ = net.Dial("tcp", "host:80") }`,
		`import "net"
func x() { _, _ = net.DialTimeout("tcp", "host:80", 0) }`,
		`import "crypto/tls"
func x() { _, _ = tls.Dial("tcp", "host:443", nil) }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, pkgPrefix+src)
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestGo_EnvRead_CredentialFilter(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"os.Getenv",
			`import "os"
func x() string { return os.Getenv("AWS_ACCESS_KEY_ID") }`,
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"os.LookupEnv",
			`import "os"
func x() (string, bool) { return os.LookupEnv("GITHUB_TOKEN") }`,
			[]string{"GITHUB_TOKEN"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, pkgPrefix+tc.src)
			for _, want := range tc.want {
				if _, ok := f.EnvReads[want]; !ok {
					t.Errorf("expected env-read %q, got %v", want, envReads(f))
				}
			}
		})
	}
}

func TestGo_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		`import "os"
func x() { _ = os.WriteFile("/tmp/x", []byte("y"), 0644) }`,
		`import "os"
func x() { _, _ = os.Create("/tmp/x") }`,
		`import "os"
func x() { _, _ = os.OpenFile("/tmp/x", os.O_WRONLY|os.O_CREATE, 0644) }`,
		`import "os"
func x() { _ = os.Rename("a", "/etc/b") }`,
		`import "os"
func x() { _ = os.Symlink("a", "/usr/local/b") }`,
		`import "io/ioutil"
func x() { _ = ioutil.WriteFile("/tmp/x", []byte("y"), 0644) }`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, pkgPrefix+src)
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestGo_RawIPLiteral(t *testing.T) {
	src := pkgPrefix + `var url = "https://1.2.3.4/payload"
`
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral, got %v", capList(f))
	}
}

func TestGo_NoFalsePositive(t *testing.T) {
	src := pkgPrefix + `
import (
	"encoding/json"
	"log"
)

type Greeting struct {
	Msg string ` + "`json:\"msg\"`" + `
}

func hello(name string) []byte {
	g := Greeting{Msg: "hi " + name}
	b, err := json.Marshal(g)
	if err != nil {
		log.Println("marshal:", err)
		return nil
	}
	return b
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
