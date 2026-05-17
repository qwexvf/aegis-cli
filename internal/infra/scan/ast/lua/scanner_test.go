package lua_test

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/lua"
)

func newScanner(t *testing.T) *lua.Scanner {
	t.Helper()
	s, err := lua.New()
	if err != nil {
		t.Fatalf("lua.New: %v", err)
	}
	return s
}

func caps(t *testing.T, src string) map[domain.Capability]struct{} {
	t.Helper()
	s := newScanner(t)
	f := &ast.Findings{Capabilities: map[domain.Capability]struct{}{}}
	s.AnalyzeFile("test.lua", []byte(src), f)
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

func TestShellSpawn_OsExecute(t *testing.T) {
	hasCap(t, `os.execute("ls")`, domain.CapShellSpawn)
}

func TestShellSpawn_IoPopen(t *testing.T) {
	hasCap(t, `local h = io.popen("uname -a")`, domain.CapShellSpawn)
}

func TestShellSpawn_VimFnSystem(t *testing.T) {
	hasCap(t, `vim.fn.system({"git", "status"})`, domain.CapShellSpawn)
}

func TestShellSpawn_VimFnJobstart(t *testing.T) {
	hasCap(t, `vim.fn.jobstart("nvr --remote")`, domain.CapShellSpawn)
}

func TestShellSpawn_VimSystem(t *testing.T) {
	hasCap(t, `vim.system({"echo", "hi"})`, domain.CapShellSpawn)
}

func TestDynamicEval_Loadstring(t *testing.T) {
	hasCap(t, `loadstring("return 1+1")()`, domain.CapDynamicEval)
}

func TestDynamicEval_Load(t *testing.T) {
	hasCap(t, `local f = load("return 42")`, domain.CapDynamicEval)
}

func TestDynamicEval_Loadfile(t *testing.T) {
	hasCap(t, `dofile("/tmp/x.lua")`, domain.CapDynamicEval)
}

func TestDynamicEval_VimApiNvimExec(t *testing.T) {
	hasCap(t, `vim.api.nvim_exec("echo hi", false)`, domain.CapDynamicEval)
}

func TestDynamicEval_VimApiNvimExec2(t *testing.T) {
	hasCap(t, `vim.api.nvim_exec2(":let g:x = 1", {})`, domain.CapDynamicEval)
}

func TestNetEgress_RequireSocketHttp(t *testing.T) {
	hasCap(t, `local http = require("socket.http")`, domain.CapNetEgress)
}

func TestNetEgress_RequireSslHttps(t *testing.T) {
	hasCap(t, `local https = require("ssl.https")`, domain.CapNetEgress)
}

func TestNetEgress_VimLoopNewTcp(t *testing.T) {
	hasCap(t, `local s = vim.loop.new_tcp()`, domain.CapNetEgress)
}

func TestNetEgress_VimUvNewTcp(t *testing.T) {
	hasCap(t, `local s = vim.uv.new_tcp()`, domain.CapNetEgress)
}

func TestEnvRead_OsGetenv(t *testing.T) {
	hasCap(t, `local home = os.getenv("HOME")`, domain.CapEnvRead)
}

func TestEnvRead_VimEnv(t *testing.T) {
	hasCap(t, `local tok = vim.env.GITHUB_TOKEN`, domain.CapEnvRead)
}

func TestFSWrite_IoOpen(t *testing.T) {
	hasCap(t, `local f = io.open("/tmp/x", "w")`, domain.CapFSWriteOutsideRoot)
}

func TestFSWrite_VimFnWritefile(t *testing.T) {
	hasCap(t, `vim.fn.writefile({"line"}, "/tmp/log.txt")`, domain.CapFSWriteOutsideRoot)
}

func TestInstallHookExec_FfiLoad(t *testing.T) {
	hasCap(t, `local lib = ffi.load("hostile.so")`, domain.CapInstallHookExec)
}

func TestInstallHookExec_PackageCpath(t *testing.T) {
	hasCap(t, `package.cpath = package.cpath .. ";/tmp/?.so"`, domain.CapInstallHookExec)
}

func TestRawIPLiteral_Match(t *testing.T) {
	hasCap(t, `local c2 = "http://192.168.1.1/beacon"`, domain.CapRawIPLiteral)
}

func TestRawIPLiteral_NoMatch_Domain(t *testing.T) {
	noCap(t, `local url = "https://example.com/api"`, domain.CapRawIPLiteral)
}

func TestCleanFile_NoCaps(t *testing.T) {
	got := caps(t, `
local M = {}

function M.hello()
  print("hello")
  return 42
end

return M
`)
	if len(got) != 0 {
		t.Errorf("expected no capabilities for clean file, got %v", got)
	}
}
