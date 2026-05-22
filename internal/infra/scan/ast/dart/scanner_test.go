package dart_test

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/dart"
)

func newScanner(t *testing.T) *dart.Scanner {
	t.Helper()
	s, err := dart.New()
	if err != nil {
		t.Fatalf("dart.New: %v", err)
	}
	return s
}

func caps(t *testing.T, src string) map[domain.Capability]struct{} {
	t.Helper()
	s := newScanner(t)
	f := &ast.Findings{Capabilities: map[domain.Capability]struct{}{}}
	s.AnalyzeFile("test.dart", []byte(src), f)
	return f.Capabilities
}

func hasCap(t *testing.T, src string, want domain.Capability) {
	t.Helper()
	if _, ok := caps(t, src)[want]; !ok {
		t.Errorf("expected %s capability, got none\nsrc:\n%s", want, src)
	}
}

func noCap(t *testing.T, src string, unwanted domain.Capability) {
	t.Helper()
	if _, ok := caps(t, src)[unwanted]; ok {
		t.Errorf("unexpected %s capability", unwanted)
	}
}

func TestNew_NoError(t *testing.T) { newScanner(t) }

func TestProcess_ShellSpawn(t *testing.T) {
	hasCap(t, `
import 'dart:io';
void main() async {
  await Process.run('ls', ['-la']);
}
`, domain.CapShellSpawn)
}

func TestMirrors_DynamicEval(t *testing.T) {
	hasCap(t, `
import 'dart:mirrors';
void main() {
  var cm = reflectClass(String);
  print(cm);
}
`, domain.CapDynamicEval)
}

func TestBase64_Decode(t *testing.T) {
	hasCap(t, `
import 'dart:convert';
void main() {
  var data = base64Decode("Zm9v");
}
`, domain.CapBase64Decode)
}

func TestHttpClient_NetEgress(t *testing.T) {
	hasCap(t, `
import 'dart:io';
void main() async {
  var client = HttpClient();
  await client.getUrl(Uri.parse("http://example.com"));
}
`, domain.CapNetEgress)
}

func TestSocket_NetEgress(t *testing.T) {
	hasCap(t, `
import 'dart:io';
void main() async {
  await Socket.connect("1.2.3.4", 9000);
}
`, domain.CapNetEgress)
}

func TestPlatform_EnvRead(t *testing.T) {
	hasCap(t, `
import 'dart:io';
void main() {
  var env = Platform.environment["HOME"];
}
`, domain.CapEnvRead)
}

func TestFile_FSWrite(t *testing.T) {
	hasCap(t, `
import 'dart:io';
void main() async {
  await File("/tmp/x").writeAsString("data");
}
`, domain.CapFSWriteOutsideRoot)
}

func TestRawIPLiteral_Match(t *testing.T) {
	hasCap(t, `final url = "http://192.168.1.1/beacon";`, domain.CapRawIPLiteral)
}

func TestRawIPLiteral_NoMatch_Domain(t *testing.T) {
	noCap(t, `final url = "https://example.com/api";`, domain.CapRawIPLiteral)
}

func TestCleanFile_NoCaps(t *testing.T) {
	got := caps(t, `
void main() {
  print("hello");
  var x = 1 + 2;
}
`)
	if len(got) != 0 {
		t.Errorf("expected no capabilities, got %v", got)
	}
}
