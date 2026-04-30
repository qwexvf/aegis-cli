//go:build windows

package atomicwrite

// syncDir is a no-op on Windows. The NTFS rename semantics differ from
// POSIX, and there is no portable equivalent of fsync'ing a directory
// handle. The CLI is not officially supported on Windows today; this
// stub exists only so cross-platform builds compile.
func syncDir(string) error { return nil }
