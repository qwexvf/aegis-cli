//go:build !nopnpm

package main

import "github.com/qwexvf/aegis-cli/internal/infra/pmwrapper"

func init() { registerPM(pmwrapper.NewPnpm()) }
