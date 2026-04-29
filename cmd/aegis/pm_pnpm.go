//go:build !nopnpm

package main

import "github.com/qwexvf/aegis/services/cli/internal/infra/pmwrapper"

func init() { registerPM(pmwrapper.NewPnpm()) }
