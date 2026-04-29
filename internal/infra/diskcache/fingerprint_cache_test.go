package diskcache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

func tmpFPCache(t *testing.T) *FingerprintCache {
	t.Helper()
	return NewFingerprintCacheAt(filepath.Join(t.TempDir(), "fp"))
}

func TestFingerprintCache_GetMiss(t *testing.T) {
	c := tmpFPCache(t)
	if _, ok := c.Get(domain.EcoNpm, "lodash", "4.17.21"); ok {
		t.Error("Get on empty cache should miss")
	}
}

func TestFingerprintCache_RoundTripPreservesEverything(t *testing.T) {
	c := tmpFPCache(t)
	want := domain.Fingerprint{
		Analyzed: true,
		Capabilities: domain.NewCapabilitySet(
			domain.CapShellSpawn,
			domain.CapDynamicEval,
			domain.CapBase64Decode,
			domain.CapNetEgress,
			domain.CapEnvRead,
			domain.CapFSWriteOutsideRoot,
			domain.CapRawIPLiteral,
			domain.CapInstallHookExec,
		),
		Hooks: []domain.InstallHook{
			{Phase: domain.PhasePreInstall, Source: "scripts.preinstall", Sha256: "deadbeef"},
			{Phase: domain.PhasePostInstall, Source: "scripts.postinstall", Sha256: "cafebabe"},
		},
		EnvReads:        []string{"AWS_ACCESS_KEY_ID", "GITHUB_TOKEN"},
		SourceSizeBytes: 9999,
		ASTSummaryHash:  "0badc0de",
	}
	if err := c.Put(domain.EcoNpm, "ua-parser-js", "0.7.29", want); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(domain.EcoNpm, "ua-parser-js", "0.7.29")
	if !ok {
		t.Fatal("expected hit after Put")
	}
	if !got.Analyzed {
		t.Error("Analyzed flag lost")
	}
	if len(got.Capabilities) != 8 {
		t.Errorf("capabilities lost: got %d, want 8", len(got.Capabilities))
	}
	for _, c := range want.Capabilities {
		if !got.Capabilities.Has(c) {
			t.Errorf("missing capability %s after roundtrip", c)
		}
	}
	if len(got.Hooks) != 2 {
		t.Errorf("hooks lost: %+v", got.Hooks)
	}
	if got.Hooks[0].Sha256 != "deadbeef" || got.Hooks[1].Sha256 != "cafebabe" {
		t.Errorf("hook sha256 lost: %+v", got.Hooks)
	}
	if got.SourceSizeBytes != 9999 || got.ASTSummaryHash != "0badc0de" {
		t.Errorf("scalar fields lost: %+v", got)
	}
	if len(got.EnvReads) != 2 {
		t.Errorf("env reads lost: %+v", got.EnvReads)
	}
}

func TestFingerprintCache_KeyIsolation(t *testing.T) {
	c := tmpFPCache(t)
	a := domain.Fingerprint{Analyzed: true, Capabilities: domain.NewCapabilitySet(domain.CapShellSpawn)}
	b := domain.Fingerprint{Analyzed: true, Capabilities: domain.NewCapabilitySet(domain.CapNetEgress)}

	c.Put(domain.EcoNpm, "lodash", "4.17.21", a)
	c.Put(domain.EcoNpm, "lodash", "4.17.20", b)  // different version
	c.Put(domain.EcoPyPI, "lodash", "4.17.21", b) // different ecosystem
	c.Put(domain.EcoNpm, "react", "4.17.21", b)   // different name

	got, _ := c.Get(domain.EcoNpm, "lodash", "4.17.21")
	if !got.Capabilities.Has(domain.CapShellSpawn) || got.Capabilities.Has(domain.CapNetEgress) {
		t.Errorf("entries leaked between keys: %+v", got)
	}
}

func TestFingerprintCache_PathIsBrowsable(t *testing.T) {
	c := tmpFPCache(t)
	c.Put(domain.EcoNpm, "@scope/pkg", "1.0.0", domain.Fingerprint{Analyzed: true})
	want := filepath.Join(c.dir, "npm", "@scope", "pkg", "1.0.0.json")
	if got := c.Path(domain.EcoNpm, "@scope/pkg", "1.0.0"); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("on-disk file should exist: %v", err)
	}
}

func TestFingerprintCache_CorruptFileMisses(t *testing.T) {
	c := tmpFPCache(t)
	// Plant garbage at the canonical path.
	path := c.Path(domain.EcoNpm, "p", "1.0.0")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("not json"), 0o600)

	if _, ok := c.Get(domain.EcoNpm, "p", "1.0.0"); ok {
		t.Error("corrupt file should miss")
	}
	// Put recovers the slot.
	if err := c.Put(domain.EcoNpm, "p", "1.0.0", domain.Fingerprint{Analyzed: true}); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(domain.EcoNpm, "p", "1.0.0")
	if !ok || !got.Analyzed {
		t.Error("expected recovery after Put on corrupt slot")
	}
}

func TestFingerprintCache_EmptyFingerprintRoundTrip(t *testing.T) {
	c := tmpFPCache(t)
	if err := c.Put(domain.EcoNpm, "p", "1.0.0", domain.Fingerprint{}); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(domain.EcoNpm, "p", "1.0.0")
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Analyzed {
		t.Error("Analyzed should round-trip as false")
	}
	if len(got.Capabilities) != 0 || len(got.Hooks) != 0 {
		t.Error("empty fingerprint should not gain content")
	}
}

func TestFingerprintCache_AtomicPutVisibility(t *testing.T) {
	// While Put is mid-write, concurrent Get must see either old or
	// new but never partial. We can't truly race os.Rename in a unit
	// test, but at least check that 50 concurrent Puts produce a
	// readable file each time.
	c := tmpFPCache(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fp := domain.Fingerprint{Analyzed: true, SourceSizeBytes: i}
			if err := c.Put(domain.EcoNpm, "race", "1.0.0", fp); err != nil {
				t.Errorf("Put failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
	got, ok := c.Get(domain.EcoNpm, "race", "1.0.0")
	if !ok {
		t.Error("expected hit after concurrent puts")
	}
	if !got.Analyzed {
		t.Error("post-race fingerprint should be analyzed")
	}
}

func TestFingerprintCache_ClearRemovesEverything(t *testing.T) {
	c := tmpFPCache(t)
	c.Put(domain.EcoNpm, "a", "1.0.0", domain.Fingerprint{Analyzed: true})
	c.Put(domain.EcoNpm, "b", "1.0.0", domain.Fingerprint{Analyzed: true})

	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(domain.EcoNpm, "a", "1.0.0"); ok {
		t.Error("a should be cleared")
	}
	if _, ok := c.Get(domain.EcoNpm, "b", "1.0.0"); ok {
		t.Error("b should be cleared")
	}
	// Clear on already-empty cache is a no-op, not an error.
	if err := c.Clear(); err != nil {
		t.Errorf("Clear on missing dir errored: %v", err)
	}
}

func TestFingerprintCache_NewReadsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AEGIS_CACHE_DIR", dir)
	c := NewFingerprintCache()
	want := filepath.Join(dir, "fingerprints", "npm", "p", "1.0.0.json")
	if got := c.Path(domain.EcoNpm, "p", "1.0.0"); got != want {
		t.Errorf("Path under AEGIS_CACHE_DIR = %q, want %q", got, want)
	}
}
