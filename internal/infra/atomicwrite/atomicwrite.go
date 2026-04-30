// Package atomicwrite is the canonical helper for crash-safe file
// writes. Every persisted artefact in the CLI (decisions cache,
// fingerprint cache, snapshot lockfile, tarball cache entries) goes
// through this package so the same durability contract applies
// uniformly.
//
// Contract: on successful return, the destination either contains the
// full new contents or the previous contents — never a truncated
// half-write. Achieved via the standard tmp-write → fsync(file) →
// rename → fsync(parent-dir) recipe. Parent-directory fsync is what
// makes the rename itself durable on POSIX; without it, a crash
// between rename and the next dir flush can lose the rename.
package atomicwrite

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFile durably writes data to path. The destination directory
// must already exist; callers that need MkdirAll should call it
// themselves so failure modes (perm errors vs disk-full) stay
// distinguishable.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	return WriteFileFunc(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteFileFunc is the streaming variant: write produces bytes via the
// provided writer. Used for compressed payloads (zstd snapshot) and
// any case where a callable wants to stream rather than allocate the
// full buffer up-front.
//
// Errors from write are propagated; the temp file is removed.
func WriteFileFunc(path string, perm os.FileMode, write func(io.Writer) error) (retErr error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("atomicwrite: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("atomicwrite: chmod: %w", err)
	}
	if err := write(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("atomicwrite: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("atomicwrite: fsync file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicwrite: close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomicwrite: rename: %w", err)
	}
	cleanup = false
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("atomicwrite: fsync dir: %w", err)
	}
	return nil
}

// MkdirAll wraps os.MkdirAll for callers that always want to ensure
// the destination's parent exists in one step. Kept here so call sites
// don't need to import path/filepath alongside atomicwrite.
func MkdirAll(dir string, perm os.FileMode) error {
	if err := os.MkdirAll(dir, perm); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}
