//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package ui

func isTerminal(fd uintptr) bool { return false }
