// Package hookfs is the on-disk adapter for usecase.HookFilesystem.
// Trivial wrapper around os calls — exists so the use case takes a
// port (testable with an in-memory fake) instead of os directly.
package hookfs

import "os"

// FS satisfies usecase.HookFilesystem against the real filesystem.
type FS struct{}

func New() *FS { return &FS{} }

func (FS) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
func (FS) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (FS) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
func (FS) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (FS) Remove(path string) error                     { return os.Remove(path) }
