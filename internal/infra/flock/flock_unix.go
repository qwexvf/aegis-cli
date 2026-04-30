//go:build unix

package flock

import (
	"os"
	"syscall"
)

// LockExclusive takes an exclusive flock(2) lock on f. Returns a
// release function. Blocks until the lock is acquired.
func LockExclusive(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}, nil
}
