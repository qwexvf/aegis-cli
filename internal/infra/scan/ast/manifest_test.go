package ast

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestNpmManifestHooks_AllPhases(t *testing.T) {
	manifest := []byte(`{
		"name": "demo",
		"scripts": {
			"preinstall":  "echo pre",
			"install":     "echo install",
			"postinstall": "echo post",
			"prepare":     "echo prep",
			"test":        "echo test"
		}
	}`)
	hooks := manifestHooks(domain.EcoNpm, manifest)
	if len(hooks) != 4 {
		t.Fatalf("expected 4 install hooks, got %d: %+v", len(hooks), hooks)
	}
	// Phases: preinstall(1), then 3 postinstall (install/postinstall/prepare).
	if hooks[0].Phase != domain.PhasePreInstall {
		t.Errorf("first hook phase = %s, want preinstall", hooks[0].Phase)
	}
	for _, h := range hooks {
		if h.Sha256 == "" {
			t.Errorf("hook %s missing Sha256", h.Source)
		}
	}
}

func TestNpmManifestHooks_TestScriptIgnored(t *testing.T) {
	manifest := []byte(`{"scripts": {"test": "jest"}}`)
	hooks := manifestHooks(domain.EcoNpm, manifest)
	if len(hooks) != 0 {
		t.Errorf("test script should be ignored, got %+v", hooks)
	}
}

func TestNpmManifestHooks_NoScripts(t *testing.T) {
	manifest := []byte(`{"name": "demo"}`)
	if hooks := manifestHooks(domain.EcoNpm, manifest); len(hooks) != 0 {
		t.Errorf("no scripts should yield no hooks, got %+v", hooks)
	}
}

func TestNpmManifestHooks_HookSha256Stable(t *testing.T) {
	a := manifestHooks(domain.EcoNpm, []byte(`{"scripts":{"postinstall":"node a.js"}}`))
	b := manifestHooks(domain.EcoNpm, []byte(`{"scripts":{"postinstall":"node a.js"}}`))
	c := manifestHooks(domain.EcoNpm, []byte(`{"scripts":{"postinstall":"node b.js"}}`))
	if a[0].Sha256 != b[0].Sha256 {
		t.Errorf("identical scripts should yield identical sha")
	}
	if a[0].Sha256 == c[0].Sha256 {
		t.Errorf("different scripts must yield different sha")
	}
}

func TestNpmManifestHooks_MalformedManifest(t *testing.T) {
	if hooks := manifestHooks(domain.EcoNpm, []byte("not json")); hooks != nil {
		t.Errorf("malformed manifest should yield nil, got %+v", hooks)
	}
}

func TestManifestHooks_NoOpForUnsupportedEcosystems(t *testing.T) {
	if hooks := manifestHooks(domain.EcoPyPI, []byte(`anything`)); hooks != nil {
		t.Errorf("pypi not yet supported, expected nil, got %+v", hooks)
	}
}
