//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package cli

func isTerminal(fd uintptr) bool { return false }
