//go:build darwin || freebsd || netbsd || openbsd

package ui

import "syscall"

const ioctlReadTermios = syscall.TIOCGETA
