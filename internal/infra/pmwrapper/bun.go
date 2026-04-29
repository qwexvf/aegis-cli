package pmwrapper

import "github.com/qwexvf/aegis/services/cli/internal/domain"

// Bun wraps the `bun` CLI. bun reads the npm registry and supports the
// same scoped-name@version spec syntax, so the parser is shared. Only
// the install-subcommand list and flag table differ.
type Bun struct{}

// NewBun returns the bun package manager.
func NewBun() *Bun { return &Bun{} }

func (Bun) Name() string                { return "bun" }
func (Bun) Ecosystem() domain.Ecosystem { return domain.EcoNpm }
func (Bun) InstallVerb() string         { return "add" }

func (Bun) IsInstallCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "install", "i", "add", "a":
		return true
	}
	return false
}

func (Bun) ParseInstallArgs(argv []string) []SpecToken {
	if len(argv) == 0 {
		return nil
	}
	return ParseInstallArgsWith(argv[1:], bunTakesValue)
}

func bunTakesValue(flag string) bool {
	switch flag {
	case "--cwd",
		"--config", "-c",
		"--registry",
		"--token",
		"--filter",
		"--lockfile-version":
		return true
	}
	return false
}

func (Bun) Exec(args []string) error {
	return execPassthrough("bun", args)
}
