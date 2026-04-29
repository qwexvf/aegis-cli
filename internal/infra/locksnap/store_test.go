package locksnap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

func newStoreT(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func sample() domain.Snapshot {
	return domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		AegisVersion:  "test",
		Project:       "demo",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Direct: true, Integrity: "sha512-abc"},
			{Ecosystem: domain.EcoNpm, Name: "ms", Version: "2.1.3"},
		},
	}
}

func TestStore_RoundTrip(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()

	want := sample()
	if err := store.Save(dir, want); err != nil {
		t.Fatal(err)
	}

	got, ok, err := store.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected snapshot to be present")
	}
	if got.SchemaVersion != want.SchemaVersion ||
		got.Project != want.Project ||
		len(got.Deps) != len(want.Deps) {
		t.Errorf("roundtrip mismatch:\n want %+v\n got  %+v", want, got)
	}
	if got.Deps[0].Name != "lodash" || got.Deps[0].Integrity != "sha512-abc" || !got.Deps[0].Direct {
		t.Errorf("dep[0] lost data: %+v", got.Deps[0])
	}
}

func TestStore_FilePathIsAegisLock(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()
	store.Save(dir, sample())

	if _, err := os.Stat(filepath.Join(dir, "aegis.lock")); err != nil {
		t.Errorf("aegis.lock not at project root: %v", err)
	}
}

func TestStore_LoadMissingReturnsFalseNoErr(t *testing.T) {
	store := newStoreT(t)
	_, ok, err := store.Load(t.TempDir())
	if err != nil {
		t.Errorf("Load missing snapshot errored: %v", err)
	}
	if ok {
		t.Errorf("Load missing snapshot reported ok=true")
	}
}

func TestStore_AcceptsPlainJSON(t *testing.T) {
	// Hand-write a plain (uncompressed) JSON file at the canonical
	// location and make sure Load tolerates it. Useful for tests / debug.
	store := newStoreT(t)
	dir := t.TempDir()
	plain := []byte(`{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "deps": [{"ecosystem":"npm","name":"lodash","version":"4.17.21"}]
}`)
	if err := os.WriteFile(filepath.Join(dir, "aegis.lock"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Load(dir)
	if err != nil || !ok {
		t.Fatalf("plain JSON load failed: ok=%v err=%v", ok, err)
	}
	if len(got.Deps) != 1 || got.Deps[0].Name != "lodash" {
		t.Errorf("plain JSON content lost: %+v", got)
	}
}

func TestStore_CorruptFileErrors(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "aegis.lock"), []byte("garbage that is not zstd or json"), 0o600)

	_, _, err := store.Load(dir)
	if err == nil {
		t.Error("expected error on corrupt file")
	}
}

func TestStore_PreservesFingerprint(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()

	src := domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Deps: []domain.Dependency{{
			Ecosystem: domain.EcoNpm,
			Name:      "ua-parser-js",
			Version:   "0.7.29",
			Fingerprint: &domain.Fingerprint{
				HasInstallScript: true,
				ShellCalls:       3,
				NetCalls:         1,
				EnvReads:         []string{"AWS_ACCESS_KEY_ID"},
				ObfuscationScore: 0.87,
			},
		}},
	}
	store.Save(dir, src)

	got, _, _ := store.Load(dir)
	fp := got.Deps[0].Fingerprint
	if fp == nil || !fp.HasInstallScript || fp.ShellCalls != 3 || fp.ObfuscationScore != 0.87 {
		t.Errorf("fingerprint lost on roundtrip: %+v", fp)
	}
}

func TestStore_CompressionShrinksLargeSnapshot(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()

	deps := make([]domain.Dependency, 500)
	for i := range deps {
		deps[i] = domain.Dependency{
			Ecosystem: domain.EcoNpm,
			Name:      "package-with-a-reasonably-long-name-to-amplify-bytes",
			Version:   "1.2.3",
			Integrity: "sha512-Abcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz==",
		}
	}
	store.Save(dir, domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		Deps:          deps,
	})

	stat, _ := os.Stat(filepath.Join(dir, "aegis.lock"))
	// 500 deps with that name+integrity is ~75KB raw JSON. zstd should
	// shrink that to under 5KB. We assert a generous upper bound to
	// avoid flakes.
	if stat.Size() > 10_000 {
		t.Errorf("zstd compression looks too weak: %d bytes (expected <10KB for 500-dep dummy)", stat.Size())
	}
}
