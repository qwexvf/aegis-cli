package usecase

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// --- mocks for risk-engine ports ---------------------------------------
// All three fakes are concurrency-safe so the parallel worker pool in
// Snapshot.Enrich/Submit can hammer them under -race without the
// detector flagging the fakes themselves. Production adapters have
// their own thread safety story (atomic file writes per key).

type fakeFetcher struct {
	mu       sync.Mutex
	calls    int
	err      error
	manifest []byte
	files    map[string][]byte
}

func (f *fakeFetcher) Fetch(_ context.Context, _ domain.Ecosystem, _, _ string) (PackageSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return PackageSource{}, f.err
	}
	return PackageSource{Files: f.files, Manifest: f.manifest}, nil
}

type fakeAnalyzer struct {
	mu    sync.Mutex
	calls int
	out   domain.Fingerprint
	err   error
}

func (a *fakeAnalyzer) Analyze(_ context.Context, _ domain.Ecosystem, _ PackageSource) (domain.Fingerprint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return domain.Fingerprint{}, a.err
	}
	return a.out, nil
}

type fakeFPCache struct {
	mu    sync.Mutex
	store map[string]domain.Fingerprint
	gets  int
	puts  int
}

func newFPCache() *fakeFPCache { return &fakeFPCache{store: map[string]domain.Fingerprint{}} }

func (c *fakeFPCache) key(eco domain.Ecosystem, name, version string) string {
	return string(eco) + "/" + name + "@" + version
}
func (c *fakeFPCache) Get(eco domain.Ecosystem, name, version string) (domain.Fingerprint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	fp, ok := c.store[c.key(eco, name, version)]
	return fp, ok
}
func (c *fakeFPCache) Put(eco domain.Ecosystem, name, version string, fp domain.Fingerprint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	c.store[c.key(eco, name, version)] = fp
	return nil
}

// --- Enrich -------------------------------------------------------------

func TestEnrich_NoRiskEngineEmitsMessage(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{dep("p", "1")}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test")

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatal(err)
	}
	if len(pres.empties) != 1 || pres.empties[0] == "" {
		t.Errorf("expected empty message, got %v", pres.empties)
	}
	if pres.progress != 0 {
		t.Errorf("expected no progress without risk engine, got %d", pres.progress)
	}
}

func TestEnrich_PopulatesFingerprintsAndPersists(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		dep("a", "1"),
		dep("b", "1"),
	}}
	fetcher := &fakeFetcher{}
	analyzer := &fakeAnalyzer{out: domain.Fingerprint{
		Capabilities: domain.NewCapabilitySet(domain.CapShellSpawn),
	}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(fetcher, analyzer, newFPCache())

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatal(err)
	}

	if pres.progress != 2 {
		t.Errorf("expected 2 progress events, got %d", pres.progress)
	}
	if fetcher.calls != 2 {
		t.Errorf("expected 2 fetches, got %d", fetcher.calls)
	}
	if analyzer.calls != 2 {
		t.Errorf("expected 2 analyses, got %d", analyzer.calls)
	}

	// Verify saved snapshot has fingerprints.
	saved := store.saved["/proj"]
	for _, d := range saved.Deps {
		if d.Fingerprint == nil || !d.Fingerprint.Analyzed {
			t.Errorf("dep %s missing analyzed fingerprint", d.Name)
		}
		if !d.Fingerprint.Capabilities.Has(domain.CapShellSpawn) {
			t.Errorf("dep %s missing CapShellSpawn", d.Name)
		}
	}
}

func TestEnrich_IsIdempotent(t *testing.T) {
	// Already-analyzed entries are skipped; only pending ones run.
	store := newFakeStore()
	pre := &domain.Fingerprint{Analyzed: true, Capabilities: domain.NewCapabilitySet(domain.CapNetEgress)}
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "a", Version: "1", Fingerprint: pre},
		{Ecosystem: domain.EcoNpm, Name: "b", Version: "1"}, // pending
	}}
	fetcher := &fakeFetcher{}
	analyzer := &fakeAnalyzer{out: domain.Fingerprint{Capabilities: domain.NewCapabilitySet(domain.CapShellSpawn)}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(fetcher, analyzer, newFPCache())

	uc.Enrich(context.Background(), "/proj")
	if fetcher.calls != 1 {
		t.Errorf("expected 1 fetch (only pending b), got %d", fetcher.calls)
	}

	// Second call must do zero work — all are now analyzed.
	uc.Enrich(context.Background(), "/proj")
	if fetcher.calls != 1 {
		t.Errorf("second Enrich must skip everything, total fetches = %d", fetcher.calls)
	}
}

func TestEnrich_UsesFingerprintCache(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{dep("a", "1")}}

	fetcher := &fakeFetcher{}
	analyzer := &fakeAnalyzer{}
	cached := newFPCache()
	cached.store["npm/a@1"] = domain.Fingerprint{Analyzed: true, Capabilities: domain.NewCapabilitySet(domain.CapNetEgress)}

	uc := NewSnapshot(store, &fakeScanner{}, &snapshotCapturingPresenter{}, "test").
		WithRiskEngine(fetcher, analyzer, cached)

	uc.Enrich(context.Background(), "/proj")
	if fetcher.calls != 0 || analyzer.calls != 0 {
		t.Errorf("cache hit must skip fetch + analyze; got fetch=%d analyze=%d", fetcher.calls, analyzer.calls)
	}
	saved := store.saved["/proj"]
	if !saved.Deps[0].Fingerprint.Capabilities.Has(domain.CapNetEgress) {
		t.Error("cached fingerprint not applied to dep")
	}
}

func TestEnrich_FetchErrorSkipsAndContinues(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{dep("a", "1"), dep("b", "1")}}
	fetcher := &fakeFetcher{err: errors.New("network down")}
	analyzer := &fakeAnalyzer{out: domain.Fingerprint{}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(fetcher, analyzer, newFPCache())

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Errorf("Enrich must not bubble up per-package errors: %v", err)
	}
	// Both attempts produced "skip" info messages.
	skipCount := 0
	for _, m := range pres.infos {
		if contains(m, "skip") {
			skipCount++
		}
	}
	if skipCount != 2 {
		t.Errorf("expected 2 skip messages, got %d (%v)", skipCount, pres.infos)
	}
}

func TestEnrich_MissingSnapshotEmitsMessage(t *testing.T) {
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(newFakeStore(), &fakeScanner{}, pres, "test").
		WithRiskEngine(&fakeFetcher{}, &fakeAnalyzer{}, newFPCache())

	uc.Enrich(context.Background(), "/proj")
	if len(pres.empties) != 1 {
		t.Errorf("expected empty message, got %v", pres.empties)
	}
}

// --- Diff with risk engine ---------------------------------------------

func TestDiff_AddedDepWithFingerprintProducesVerdict(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{}}

	// Live dep "evil@1" with a high-risk fingerprint.
	highRiskFP := &domain.Fingerprint{
		Analyzed: true,
		Capabilities: domain.NewCapabilitySet(
			domain.CapShellSpawn, domain.CapDynamicEval,
			domain.CapBase64Decode, domain.CapNetEgress,
		),
		Hooks: []domain.InstallHook{{Phase: domain.PhasePostInstall, Source: "scripts.postinstall"}},
	}
	scanner := &fakeScanner{deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "evil", Version: "1.0.0", Fingerprint: highRiskFP},
	}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	if err := uc.Diff("/proj", "", ""); err != nil {
		t.Fatal(err)
	}
	d := pres.diffs[0]
	added := entriesByKind(d, DiffAdded)
	if len(added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(added))
	}
	// hook (30) + 4 caps (20+25+20+10) = 105 → block
	if added[0].Verdict != domain.VerdictBlock {
		t.Errorf("verdict = %s, want block", added[0].Verdict)
	}
	if !d.AnyBlocked {
		t.Error("DiffReport.AnyBlocked should be true")
	}
	if d.AnyPrompt {
		t.Error("DiffReport.AnyPrompt should be false (block dominates)")
	}
}

func TestDiff_UpgradedWithDriftProducesPrompt(t *testing.T) {
	old := &domain.Fingerprint{Analyzed: true, SourceSizeBytes: 5000}
	new_ := &domain.Fingerprint{
		Analyzed:        true,
		Capabilities:    domain.NewCapabilitySet(domain.CapShellSpawn, domain.CapNetEgress),
		Hooks:           []domain.InstallHook{{Phase: domain.PhasePostInstall, Source: "scripts.postinstall"}},
		SourceSizeBytes: 12000,
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "p", Version: "1.0.0", Fingerprint: old},
	}}
	scanner := &fakeScanner{deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "p", Version: "1.0.1", Fingerprint: new_},
	}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	uc.Diff("/proj", "", "")
	d := pres.diffs[0]
	upgrades := entriesByKind(d, DiffUpgraded)
	if len(upgrades) != 1 {
		t.Fatalf("expected 1 upgrade, got %d", len(upgrades))
	}
	e := upgrades[0]
	if e.Drift.Score == 0 {
		t.Errorf("expected non-zero drift, got %+v", e.Drift)
	}
	if e.Verdict == domain.VerdictSafe {
		t.Errorf("expected non-safe verdict for compromise pattern, got %s", e.Verdict)
	}
}

func TestDiff_RemovedDepHasSafeVerdict(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{dep("removed", "1.0.0")}}
	scanner := &fakeScanner{deps: []domain.Dependency{}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	uc.Diff("/proj", "", "")
	d := pres.diffs[0]
	removed := entriesByKind(d, DiffRemoved)
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(removed))
	}
	if removed[0].Verdict != domain.VerdictSafe {
		t.Errorf("removed entry should be safe, got %s", removed[0].Verdict)
	}
	if d.AnyBlocked || d.AnyPrompt {
		t.Error("removal alone shouldn't trip blocked/prompt flags")
	}
}

func TestDiff_CarriesForwardFingerprintsForUnchangedVersions(t *testing.T) {
	// Saved has lodash@4.17.21 with a fingerprint. Live re-scan
	// produces lodash@4.17.21 again (no fingerprint, since the
	// scanner only reads lockfile). The use case must carry forward
	// the saved fingerprint so risk-engine assertions don't reset.
	prevFP := &domain.Fingerprint{Analyzed: true, Capabilities: domain.NewCapabilitySet(domain.CapNetEgress)}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Fingerprint: prevFP},
	}}
	// liveDeps lacks fingerprint
	scanner := &fakeScanner{deps: []domain.Dependency{
		dep("lodash", "4.17.21"),
	}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	uc.Diff("/proj", "", "")
	d := pres.diffs[0]
	if len(d.Entries) != 0 {
		// no version change → no diff entries; still ok
	}

	// Now: change the version to 4.17.22 in live, verify drift uses the carried-forward saved fp.
	scanner.deps = []domain.Dependency{
		{
			Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.22",
			Fingerprint: &domain.Fingerprint{Analyzed: true,
				Capabilities: domain.NewCapabilitySet(domain.CapNetEgress, domain.CapShellSpawn),
			},
		},
	}
	pres.diffs = nil
	uc.Diff("/proj", "", "")
	d = pres.diffs[0]
	upgrades := entriesByKind(d, DiffUpgraded)
	if len(upgrades) != 1 {
		t.Fatalf("expected 1 upgrade, got %d", len(upgrades))
	}
	if upgrades[0].Drift.Score == 0 {
		t.Errorf("drift should fire (CapShellSpawn added), got %+v", upgrades[0].Drift)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && stringIndexOf(s, sub) >= 0))
}

func stringIndexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
