// Package flock is a thin cross-platform wrapper around POSIX flock(2)
// for inter-process file locking. Used by adapters that share state
// across `aegis` invocations (audit log, decisions cache).
//
// Usage pattern:
//
//	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
//	if err != nil { return err }
//	defer f.Close()
//	unlock, err := flock.LockExclusive(f)
//	if err != nil { return err }
//	defer unlock()
//	// ... critical section ...
//
// The lockfile itself can be anything writable; using a dedicated
// `<target>.lock` (rather than locking the target itself) avoids
// rename-vs-flock ordering subtleties.
package flock
