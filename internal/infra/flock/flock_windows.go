//go:build windows

package flock

import "os"

// LockExclusive is a no-op on Windows. Cross-process locking would
// need LockFileEx; the CLI is not officially supported on Windows
// today, so this stub exists only so cross-platform builds compile.
func LockExclusive(*os.File) (func(), error) { return func() {}, nil }
