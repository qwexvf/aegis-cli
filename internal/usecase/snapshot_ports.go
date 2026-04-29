package usecase

import "github.com/qwexvf/aegis/services/cli/internal/domain"

// SnapshotStore persists a snapshot to local disk. Implementation:
// infra/locksnap.
type SnapshotStore interface {
	// Save writes a snapshot to its canonical location (typically
	// aegis.lock at projectDir).
	Save(projectDir string, s domain.Snapshot) error
	// Load reads a snapshot from its canonical location, or returns
	// (zero, false, nil) if no snapshot exists yet.
	Load(projectDir string) (domain.Snapshot, bool, error)
	// LoadFile reads a snapshot from an explicit path (used for
	// `aegis snapshot diff <a> <b>`).
	LoadFile(path string) (domain.Snapshot, error)
	// Path returns the canonical save path for a project. Useful for
	// presenter output ("saved to aegis.lock").
	Path(projectDir string) string
}

// LockfileScanner reads the project's package-manager lockfile(s) and
// produces a deduplicated, sorted []Dependency. Implementation:
// infra/locksnap.
type LockfileScanner interface {
	// ScanProject autodetects the lockfile format(s) in projectDir
	// and returns the dependencies it sees. Errors only on malformed
	// input — a project with no lockfile returns ([], nil).
	ScanProject(projectDir string) ([]domain.Dependency, error)
}

// SnapshotPresenter renders snapshot operations to the user.
type SnapshotPresenter interface {
	OnSnapshotSaved(path string, depCount int)
	OnSnapshotShow(s domain.Snapshot, directOnly bool)
	OnSnapshotDiff(delta domain.SnapshotDelta)
	OnSnapshotEmpty(reason string)
	OnSnapshotInfo(message string)
	OnSnapshotError(err error)
}
