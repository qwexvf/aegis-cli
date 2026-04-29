package usecase

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// Snapshot is the use case for project snapshots: save the current
// lockfile state to disk, show it back, and diff against either the
// last saved version or any explicit pair of files.
type Snapshot struct {
	store     SnapshotStore
	scanner   LockfileScanner
	presenter SnapshotPresenter

	aegisVersion string
	now          func() time.Time // injectable for tests
}

// NewSnapshot wires a Snapshot use case.
func NewSnapshot(store SnapshotStore, scanner LockfileScanner, presenter SnapshotPresenter, aegisVersion string) *Snapshot {
	return &Snapshot{
		store:        store,
		scanner:      scanner,
		presenter:    presenter,
		aegisVersion: aegisVersion,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// Save scans the project's lockfile(s) and writes a fresh snapshot to
// the canonical location (aegis.lock).
func (s *Snapshot) Save(projectDir string) error {
	deps, err := s.scanner.ScanProject(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if len(deps) == 0 {
		s.presenter.OnSnapshotEmpty("no lockfile found in " + projectDir)
		return nil
	}

	snap := domain.Snapshot{
		SchemaVersion: domain.SnapshotSchemaVersion,
		CreatedAt:     s.now(),
		AegisVersion:  s.aegisVersion,
		Project:       filepath.Base(projectDir),
		Deps:          deps,
	}
	if err := s.store.Save(projectDir, snap); err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	s.presenter.OnSnapshotSaved(s.store.Path(projectDir), len(deps))
	return nil
}

// Show loads the saved snapshot and renders it. directOnly limits the
// display to top-level dependencies.
func (s *Snapshot) Show(projectDir string, directOnly bool) error {
	snap, ok, err := s.store.Load(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if !ok {
		s.presenter.OnSnapshotEmpty("no snapshot saved — run 'aegis snapshot save' first")
		return nil
	}
	s.presenter.OnSnapshotShow(snap, directOnly)
	return nil
}

// Diff compares two snapshots. With both arguments empty, it diffs the
// saved snapshot against a live re-scan of the project lockfile (the
// most common case: "what changed since I saved?"). With both
// arguments set, it diffs two explicit files (debug / CI use).
func (s *Snapshot) Diff(projectDir, fileA, fileB string) error {
	a, b, err := s.loadDiffOperands(projectDir, fileA, fileB)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	delta := domain.DiffSnapshots(a, b)
	s.presenter.OnSnapshotDiff(delta)
	return nil
}

func (s *Snapshot) loadDiffOperands(projectDir, fileA, fileB string) (domain.Snapshot, domain.Snapshot, error) {
	switch {
	case fileA != "" && fileB != "":
		a, err := s.store.LoadFile(fileA)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("read %s: %w", fileA, err)
		}
		b, err := s.store.LoadFile(fileB)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("read %s: %w", fileB, err)
		}
		return a, b, nil

	case fileA == "" && fileB == "":
		saved, ok, err := s.store.Load(projectDir)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, err
		}
		if !ok {
			return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("no snapshot saved — run 'aegis snapshot save' first")
		}
		liveDeps, err := s.scanner.ScanProject(projectDir)
		if err != nil {
			return domain.Snapshot{}, domain.Snapshot{}, err
		}
		live := domain.Snapshot{
			SchemaVersion: domain.SnapshotSchemaVersion,
			CreatedAt:     s.now(),
			AegisVersion:  s.aegisVersion,
			Project:       saved.Project,
			Deps:          liveDeps,
		}
		return saved, live, nil

	default:
		return domain.Snapshot{}, domain.Snapshot{}, fmt.Errorf("diff requires either zero arguments (saved vs live) or two file paths")
	}
}

// Verify checks the saved snapshot is loadable and structurally valid.
// Returns nil on success.
func (s *Snapshot) Verify(projectDir string) error {
	snap, ok, err := s.store.Load(projectDir)
	if err != nil {
		s.presenter.OnSnapshotError(err)
		return err
	}
	if !ok {
		s.presenter.OnSnapshotEmpty("no snapshot to verify")
		return nil
	}
	if snap.SchemaVersion != domain.SnapshotSchemaVersion {
		s.presenter.OnSnapshotInfo(fmt.Sprintf(
			"schema mismatch: file=%d, current=%d (re-run 'aegis snapshot save')",
			snap.SchemaVersion, domain.SnapshotSchemaVersion))
		return nil
	}
	s.presenter.OnSnapshotInfo(fmt.Sprintf(
		"snapshot OK: %d deps, schema v%d, saved %s",
		len(snap.Deps), snap.SchemaVersion, snap.CreatedAt.Format(time.RFC3339)))
	return nil
}
