package usecase

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// --- mocks --------------------------------------------------------------

type fakeStore struct {
	saved    map[string]domain.Snapshot
	files    map[string]domain.Snapshot
	loadErr  error
	saveErr  error
	loadFile func(path string) (domain.Snapshot, error)
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		saved: map[string]domain.Snapshot{},
		files: map[string]domain.Snapshot{},
	}
}
func (f *fakeStore) Save(dir string, s domain.Snapshot) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved[dir] = s
	return nil
}
func (f *fakeStore) Load(dir string) (domain.Snapshot, bool, error) {
	if f.loadErr != nil {
		return domain.Snapshot{}, false, f.loadErr
	}
	s, ok := f.saved[dir]
	return s, ok, nil
}
func (f *fakeStore) LoadFile(path string) (domain.Snapshot, error) {
	if f.loadFile != nil {
		return f.loadFile(path)
	}
	s, ok := f.files[path]
	if !ok {
		return domain.Snapshot{}, errors.New("file not found")
	}
	return s, nil
}
func (f *fakeStore) Path(dir string) string { return dir + "/aegis.lock" }

type fakeScanner struct {
	deps []domain.Dependency
	err  error
}

func (f *fakeScanner) ScanProject(string) ([]domain.Dependency, error) {
	return f.deps, f.err
}

type snapshotCapturingPresenter struct {
	mu          sync.Mutex
	saved       int
	shown       []domain.Snapshot
	diffs       []DiffReport
	progress    int
	infos       []string
	empties     []string
	errors      []error
	beginTotal  int
	beginCount  int
	endCount    int
	slotStarts  int
	slotStages  int
	slotDones   int
	slotOKCount int
}

func (p *snapshotCapturingPresenter) OnSnapshotSaved(string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saved++
}
func (p *snapshotCapturingPresenter) OnSnapshotShow(s domain.Snapshot, _, _ bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.shown = append(p.shown, s)
}
func (p *snapshotCapturingPresenter) OnSnapshotDiff(r DiffReport) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.diffs = append(p.diffs, r)
}
func (p *snapshotCapturingPresenter) OnSnapshotEnrichProgress(int, int, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.progress++
}
func (p *snapshotCapturingPresenter) OnSnapshotEmpty(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.empties = append(p.empties, reason)
}
func (p *snapshotCapturingPresenter) OnSnapshotInfo(m string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infos = append(p.infos, m)
}
func (p *snapshotCapturingPresenter) OnSnapshotError(e error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errors = append(p.errors, e)
}
func (p *snapshotCapturingPresenter) OnEnrichBegin(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beginCount++
	p.beginTotal = total
}
func (p *snapshotCapturingPresenter) OnEnrichEnd() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endCount++
}
func (p *snapshotCapturingPresenter) OnEnrichSlotStart(int, string, string, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slotStarts++
}
func (p *snapshotCapturingPresenter) OnEnrichSlotStage(int, EnrichStage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slotStages++
}
func (p *snapshotCapturingPresenter) OnEnrichSlotDone(_ int, _, _, _ string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slotDones++
	if ok {
		p.slotOKCount++
	}
}

func dep(name, ver string) domain.Dependency {
	return domain.Dependency{Ecosystem: domain.EcoNpm, Name: name, Version: ver}
}

// --- tests --------------------------------------------------------------

func TestSnapshot_SaveWritesScanResult(t *testing.T) {
	store := newFakeStore()
	scanner := &fakeScanner{deps: []domain.Dependency{dep("lodash", "4.17.21")}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	if err := uc.Save("/proj"); err != nil {
		t.Fatal(err)
	}
	if pres.saved != 1 {
		t.Errorf("expected presenter.saved=1, got %d", pres.saved)
	}
	saved, ok := store.saved["/proj"]
	if !ok || len(saved.Deps) != 1 || saved.Deps[0].Name != "lodash" {
		t.Errorf("unexpected saved snapshot: %+v", saved)
	}
	if saved.SchemaVersion != domain.SnapshotSchemaVersion {
		t.Errorf("schema version not set")
	}
}

func TestSnapshot_SaveEmptyLockfile(t *testing.T) {
	store := newFakeStore()
	scanner := &fakeScanner{deps: []domain.Dependency{}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	if err := uc.Save("/proj"); err != nil {
		t.Fatal(err)
	}
	if pres.saved != 0 {
		t.Errorf("must not save empty deps; saved=%d", pres.saved)
	}
	if len(pres.empties) != 1 || !strings.Contains(pres.empties[0], "no lockfile") {
		t.Errorf("expected empty message; got %v", pres.empties)
	}
}

func TestSnapshot_ShowLoadsSnapshot(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: []domain.Dependency{dep("lodash", "4.17.21")}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test")

	if err := uc.Show("/proj", false, false); err != nil {
		t.Fatal(err)
	}
	if len(pres.shown) != 1 {
		t.Errorf("expected 1 shown, got %d", len(pres.shown))
	}
}

func TestSnapshot_ShowMissingSnapshot(t *testing.T) {
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(newFakeStore(), &fakeScanner{}, pres, "test")

	uc.Show("/proj", false, false)
	if len(pres.empties) != 1 {
		t.Errorf("expected empty message, got %v", pres.empties)
	}
}

func TestSnapshot_DiffSavedVsLive(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{
		Deps: []domain.Dependency{dep("ua-parser-js", "0.7.28")},
	}
	scanner := &fakeScanner{deps: []domain.Dependency{dep("ua-parser-js", "0.7.29")}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, scanner, pres, "test")

	if err := uc.Diff("/proj", "", ""); err != nil {
		t.Fatal(err)
	}
	if len(pres.diffs) != 1 {
		t.Fatal("expected 1 diff")
	}
	d := pres.diffs[0]
	upgrades := entriesByKind(d, DiffUpgraded)
	if len(upgrades) != 1 || upgrades[0].Name() != "ua-parser-js" {
		t.Errorf("expected ua-parser-js upgrade, got %+v", d.Entries)
	}
}

func TestSnapshot_DiffTwoFiles(t *testing.T) {
	store := newFakeStore()
	store.files["a.lock"] = domain.Snapshot{Deps: []domain.Dependency{dep("lodash", "4.17.20")}}
	store.files["b.lock"] = domain.Snapshot{Deps: []domain.Dependency{dep("lodash", "4.17.21")}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test")

	if err := uc.Diff("/proj", "a.lock", "b.lock"); err != nil {
		t.Fatal(err)
	}
	if len(pres.diffs) != 1 || len(entriesByKind(pres.diffs[0], DiffUpgraded)) != 1 {
		t.Errorf("expected 1 upgrade, got %+v", pres.diffs)
	}
}

// entriesByKind filters DiffReport.Entries by kind for compact assertions.
func entriesByKind(r DiffReport, kind DiffEntryKind) []DiffEntry {
	var out []DiffEntry
	for _, e := range r.Entries {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestSnapshot_DiffNoSavedSnapshotErrors(t *testing.T) {
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(newFakeStore(), &fakeScanner{}, pres, "test")

	err := uc.Diff("/proj", "", "")
	if err == nil {
		t.Error("expected error when no snapshot saved")
	}
	if !strings.Contains(err.Error(), "no snapshot saved") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSnapshot_DiffOneArgErrors(t *testing.T) {
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(newFakeStore(), &fakeScanner{}, pres, "test")
	if err := uc.Diff("/proj", "only-one.lock", ""); err == nil {
		t.Error("expected error for one-argument diff")
	}
}

func TestSnapshot_VerifySchemaMismatch(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{SchemaVersion: 999, Deps: []domain.Dependency{dep("p", "1")}}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test")

	uc.Verify("/proj")
	if len(pres.infos) != 1 || !strings.Contains(pres.infos[0], "schema mismatch") {
		t.Errorf("expected schema mismatch info; got %v", pres.infos)
	}
}

func TestSnapshot_VerifyOK(t *testing.T) {
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Deps:          []domain.Dependency{dep("p", "1")},
	}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test")

	uc.Verify("/proj")
	if len(pres.infos) != 1 || !strings.Contains(pres.infos[0], "snapshot OK") {
		t.Errorf("expected ok info; got %v", pres.infos)
	}
}
