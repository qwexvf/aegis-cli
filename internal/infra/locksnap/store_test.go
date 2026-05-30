package locksnap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
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
				Analyzed: true,
				Capabilities: domain.NewCapabilitySet(
					domain.CapShellSpawn,
					domain.CapNetEgress,
					domain.CapInstallHookExec,
				),
				Hooks: []domain.InstallHook{
					{Phase: domain.PhasePostInstall, Source: "scripts.postinstall", Sha256: "abc"},
				},
				EnvReads:        []string{"AWS_ACCESS_KEY_ID"},
				SourceSizeBytes: 12345,
				ASTSummaryHash:  "deadbeef",
			},
		}},
	}
	store.Save(dir, src)

	got, _, _ := store.Load(dir)
	fp := got.Deps[0].Fingerprint
	if fp == nil || !fp.Analyzed {
		t.Fatalf("fingerprint lost: %+v", fp)
	}
	if !fp.Capabilities.Has(domain.CapShellSpawn) || !fp.Capabilities.Has(domain.CapNetEgress) {
		t.Errorf("capabilities lost: %v", fp.Capabilities)
	}
	if len(fp.Hooks) != 1 || fp.Hooks[0].Phase != domain.PhasePostInstall || fp.Hooks[0].Sha256 != "abc" {
		t.Errorf("hooks lost: %+v", fp.Hooks)
	}
	if fp.SourceSizeBytes != 12345 || fp.ASTSummaryHash != "deadbeef" {
		t.Errorf("scalar fields lost: %+v", fp)
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

// TestStore_PreservesEnrichment guards the network-fetched enrichment
// fields (advisories, license, deprecated, provenance). These were
// silently dropped by the on-disk DTO, so `aegis ci` reloaded a snapshot
// with no advisories and never gated on known CVEs. Round-trip them.
func TestStore_PreservesEnrichment(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()

	src := domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Deps: []domain.Dependency{{
			Ecosystem: domain.EcoNpm,
			Name:      "lodash",
			Version:   "4.17.4",
			Advisories: []domain.Advisory{
				{
					ID:       "GHSA-35jh-r3h4-6jhm",
					Severity: domain.SevHigh,
					Summary:  "Command Injection in lodash",
					URL:      "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
					Source:   "osv",
					FixedIn:  "4.17.21",
				},
			},
			License:             "MIT",
			Deprecated:          true,
			DeprecatedReason:    "use lodash-es",
			ProvenanceStatus:    "missing",
			ProvenanceSourceURI: "https://github.com/lodash/lodash",
			ProvenanceCommit:    "abc123",
		}},
	}
	store.Save(dir, src)

	got, _, err := store.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := got.Deps[0]
	if len(d.Advisories) != 1 {
		t.Fatalf("advisories lost: got %d, want 1", len(d.Advisories))
	}
	a := d.Advisories[0]
	if a.ID != "GHSA-35jh-r3h4-6jhm" || a.Severity != domain.SevHigh || a.FixedIn != "4.17.21" {
		t.Errorf("advisory fields lost: %+v", a)
	}
	if d.License != "MIT" {
		t.Errorf("license lost: %q", d.License)
	}
	if !d.Deprecated || d.DeprecatedReason != "use lodash-es" {
		t.Errorf("deprecated lost: %v / %q", d.Deprecated, d.DeprecatedReason)
	}
	if d.ProvenanceStatus != "missing" || d.ProvenanceCommit != "abc123" {
		t.Errorf("provenance lost: %+v", d)
	}
}

// A dep looked up and found clean keeps an (omitted→nil) advisory slice;
// a vulnerable dep keeps its advisories. Either way Save→Load must not
// invent or drop entries.
func TestStore_EnrichmentRoundTripStable(t *testing.T) {
	store := newStoreT(t)
	dir := t.TempDir()
	src := domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "clean", Version: "1.0.0"},
			{Ecosystem: domain.EcoNpm, Name: "vuln", Version: "1.0.0",
				Advisories: []domain.Advisory{{ID: "GHSA-aaaa-bbbb-cccc", Severity: domain.SevCritical}}},
		},
	}
	store.Save(dir, src)
	got, _, _ := store.Load(dir)
	if len(got.Deps[0].Advisories) != 0 {
		t.Errorf("clean dep gained advisories: %+v", got.Deps[0].Advisories)
	}
	if len(got.Deps[1].Advisories) != 1 || got.Deps[1].Advisories[0].Severity != domain.SevCritical {
		t.Errorf("vuln dep advisories lost: %+v", got.Deps[1].Advisories)
	}
}
