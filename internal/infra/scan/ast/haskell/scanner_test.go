package haskell_test

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast/haskell"
)

func newScanner(t *testing.T) *haskell.Scanner {
	t.Helper()
	s, err := haskell.New()
	if err != nil {
		t.Fatalf("haskell.New: %v", err)
	}
	return s
}

func caps(t *testing.T, src string) map[domain.Capability]struct{} {
	t.Helper()
	s := newScanner(t)
	f := &ast.Findings{Capabilities: map[domain.Capability]struct{}{}}
	s.AnalyzeFile("test.hs", []byte(src), f)
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

func TestCallCommand_ShellSpawn(t *testing.T) {
	hasCap(t, `
import System.Process
main :: IO ()
main = callCommand "ls -la"
`, domain.CapShellSpawn)
}

func TestUnsafePerformIO_DynamicEval(t *testing.T) {
	hasCap(t, `
import System.IO.Unsafe
x :: Int
x = unsafePerformIO (return 1)
`, domain.CapDynamicEval)
}

func TestForeignImport_DynamicEval(t *testing.T) {
	hasCap(t, `
foreign import ccall "math.h sin" c_sin :: Double -> Double
`, domain.CapDynamicEval)
}

func TestBase64Decode(t *testing.T) {
	hasCap(t, `
import qualified Data.ByteString.Base64 as B64
x = B64.decode "Zm9v"
`, domain.CapBase64Decode)
}

func TestHttpLBS_NetEgress(t *testing.T) {
	hasCap(t, `
import Network.HTTP.Simple
main = do
  resp <- httpLBS "http://example.com"
  return ()
`, domain.CapNetEgress)
}

func TestGetEnv_EnvRead(t *testing.T) {
	hasCap(t, `
import System.Environment
main = do
  home <- getEnv "HOME"
  return ()
`, domain.CapEnvRead)
}

func TestWriteFile_FSWrite(t *testing.T) {
	hasCap(t, `
main :: IO ()
main = writeFile "/tmp/x" "data"
`, domain.CapFSWriteOutsideRoot)
}

func TestRawIPLiteral_Match(t *testing.T) {
	hasCap(t, `c2 = "http://192.168.1.1/beacon"`, domain.CapRawIPLiteral)
}

func TestRawIPLiteral_NoMatch_Domain(t *testing.T) {
	noCap(t, `url = "https://example.com/api"`, domain.CapRawIPLiteral)
}

func TestCleanFile_NoCaps(t *testing.T) {
	got := caps(t, `
module Main where

main :: IO ()
main = putStrLn "hello"
`)
	if len(got) != 0 {
		t.Errorf("expected no capabilities, got %v", got)
	}
}
