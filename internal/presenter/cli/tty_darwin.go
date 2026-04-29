//go:build darwin || freebsd || netbsd || openbsd

package cli

import "syscall"

const ioctlReadTermios = syscall.TIOCGETA
