package ruby

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
	s.AnalyzeFile("test.rb", []byte(src), f)
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

func TestRuby_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"bare system", `system("ls")`},
		{"bare exec", `exec("ls -la")`},
		{"bare spawn", `spawn("worker")`},
		{"Kernel.system", `Kernel.system("rm -rf /")`},
		{"Process.spawn", `Process.spawn("worker")`},
		{"IO.popen", `IO.popen("ls", "r")`},
		{"Open3.capture3", `Open3.capture3("whoami")`},
		{"Open3.popen3", `Open3.popen3("rev")`},
		{"PTY.spawn", `PTY.spawn("/bin/sh")`},
		{"backticks", "`whoami`"},
		{"%x{cmd}", `%x{whoami}`},
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

func TestRuby_DynamicEval(t *testing.T) {
	for _, src := range []string{
		`eval("1+1")`,
		`eval(payload)`,
		`instance_eval("def foo; end")`,
		`class_eval { def x; end }`,
		`module_eval(remote)`,
		`obj.send(:secret_method)`,
		`x.public_send(method_name)`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapDynamicEval) {
				t.Errorf("expected CapDynamicEval for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRuby_Base64Decode(t *testing.T) {
	for _, src := range []string{
		`Base64.decode64(x)`,
		`Base64.urlsafe_decode64(x)`,
		`Base64.strict_decode64(x)`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRuby_NetEgress(t *testing.T) {
	for _, src := range []string{
		`Net::HTTP.get(URI("http://x"))`,
		`Net::HTTP.post(URI("http://x"), body)`,
		`Net::HTTP.start("host", 80) { |h| h.get("/") }`,
		`URI.open("http://x.test/p")`,
		`URI.parse("http://x.test")`,
		`open("https://example.com/p")`,
		`HTTParty.get("http://x.test")`,
		`RestClient.get("http://x.test")`,
		`Faraday.get("http://x.test")`,
		`Excon.post("http://x.test", body: "x")`,
		`TCPSocket.new("host", 80)`,
		`UDPSocket.new`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRuby_EnvRead_CredentialFilter(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"ENV subscript",
			`tok = ENV["AWS_ACCESS_KEY_ID"]`,
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"ENV.fetch with literal",
			`tok = ENV.fetch("GITHUB_TOKEN")`,
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

func TestRuby_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		`File.open("/tmp/x", "w") { |f| f.puts "y" }`,
		`File.open("foo", "a") { |f| f.puts "y" }`,
		`File.open("foo", "wb") { |f| f.write "z" }`,
		`File.write("/etc/passwd", "x")`,
		`File.binwrite("/tmp/x", payload)`,
		`IO.write("/tmp/x", "y")`,
		`FileUtils.cp("a", "/etc/b")`,
		`FileUtils.mv("a", "/root/b")`,
		`FileUtils.install("a", "/usr/local/bin/b")`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, src)
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestRuby_RawIPLiteral(t *testing.T) {
	src := `url = "https://1.2.3.4/payload"`
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral for raw-IP URL, got %v", capList(f))
	}
}

// TestRuby_NoFalsePositive verifies common benign code does NOT fire
// any capability.
func TestRuby_NoFalsePositive(t *testing.T) {
	src := `
require "json"
require "logger"

def hello(name)
  logger = Logger.new(STDOUT)
  logger.info("greeting #{name}")
  JSON.dump({greeting: "hi #{name}"})
end
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
