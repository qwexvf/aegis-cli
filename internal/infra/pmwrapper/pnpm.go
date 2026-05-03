package pmwrapper

import "github.com/qwexvf/aegis-cli/internal/domain"

// Pnpm wraps the `pnpm` CLI. pnpm reads the npm registry; the
// install-subcommand surface is similar to npm/yarn (`add`, `install`,
// `i`) plus pnpm-specific flags. `-g` / `--global` modifies the install
// scope but the package specs follow normal positional rules.
type Pnpm struct{}

// NewPnpm returns the pnpm package manager.
func NewPnpm() *Pnpm { return &Pnpm{} }

func (Pnpm) Name() string                { return "pnpm" }
func (Pnpm) Ecosystem() domain.Ecosystem { return domain.EcoNpm }
func (Pnpm) InstallVerb() string         { return "add" }

func (Pnpm) IsInstallCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "add", "install", "i":
		return true
	}
	return false
}

func (Pnpm) ParseInstallArgs(argv []string) []SpecToken {
	if len(argv) == 0 {
		return nil
	}
	return ParseInstallArgsWith(argv[1:], pnpmTakesValue)
}

func pnpmTakesValue(flag string) bool {
	switch flag {
	case "--filter", "-F",
		"--workspace", "-w",
		"--registry",
		"--store-dir",
		"--package-import-method",
		"--reporter",
		"--prefix",
		"--dir", "-C",
		"--strict-peer-dependencies":
		return true
	}
	return false
}

func (Pnpm) Exec(args []string) error {
	return execPassthrough("pnpm", args)
}
