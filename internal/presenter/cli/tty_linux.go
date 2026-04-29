//go:build linux

package cli

import "syscall"

const ioctlReadTermios = syscall.TCGETS
