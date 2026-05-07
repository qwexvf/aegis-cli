package depusagebridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/depusage"
)

func TestLanguageForExt(t *testing.T) {
	cases := []struct {
		ext  string
		want depusage.Language
		ok   bool
	}{
		{".js", depusage.JavaScript, true},
		{".tsx", depusage.TypeScript, true},
		{".py", depusage.Python, true},
		{".go", depusage.Go, true},
		{".rs", depusage.Rust, true},
		{".rb", depusage.Ruby, true},
		{".java", depusage.Java, true},
		{".php", depusage.PHP, true},
		{".cs", depusage.CSharp, true},
		{".unknown", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := LanguageForExt(c.ext)
		if got != c.want || ok != c.ok {
			t.Errorf("LanguageForExt(%q) = (%q, %v), want (%q, %v)", c.ext, got, ok, c.want, c.ok)
		}
	}
}

func TestEcosystemForLanguage(t *testing.T) {
	cases := []struct {
		lang depusage.Language
		want domain.Ecosystem
	}{
		{depusage.JavaScript, domain.EcoNpm},
		{depusage.TypeScript, domain.EcoNpm},
		{depusage.Python, domain.EcoPyPI},
		{depusage.Go, domain.EcoGo},
		{depusage.Rust, domain.EcoCrates},
		{depusage.Ruby, domain.EcoRubyGems},
		{depusage.Java, domain.EcoMaven},
		{depusage.PHP, domain.EcoPackagist},
		{depusage.CSharp, domain.EcoNuGet},
	}
	for _, c := range cases {
		got, ok := EcosystemForLanguage(c.lang)
		if !ok || got != c.want {
			t.Errorf("EcosystemForLanguage(%q) = (%q, %v), want (%q, true)", c.lang, got, ok, c.want)
		}
	}
}

func TestWalkProject_SkipsDepDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "src", "main.js"), `import _ from 'lodash';`)
	mustWrite(t, filepath.Join(root, "node_modules", "lodash", "index.js"), `module.exports = {};`)
	mustWrite(t, filepath.Join(root, "vendor", "x.go"), `package x; import "fmt"`)
	mustWrite(t, filepath.Join(root, "main.go"), `package main; import "fmt"`)
	mustWrite(t, filepath.Join(root, "README.md"), `not source`)

	var seen []string
	err := WalkProject(context.Background(), root, func(rel string, lang depusage.Language, body []byte) {
		seen = append(seen, rel)
	})
	if err != nil {
		t.Fatal(err)
	}

	wantContains := []string{filepath.Join("src", "main.js"), "main.go"}
	wantExclude := []string{
		filepath.Join("node_modules", "lodash", "index.js"),
		filepath.Join("vendor", "x.go"),
	}
	for _, w := range wantContains {
		if !contains(seen, w) {
			t.Errorf("walk should include %q, got %v", w, seen)
		}
	}
	for _, w := range wantExclude {
		if contains(seen, w) {
			t.Errorf("walk should skip %q, got %v", w, seen)
		}
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
