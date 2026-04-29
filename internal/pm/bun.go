package pm

// Bun wraps the `bun` CLI. bun reads the npm registry and supports the
// same scoped-name@version spec syntax, so the parser is shared. Only
// the install-subcommand list and flag table differ.
type Bun struct{}

// NewBun returns the bun package manager.
func NewBun() *Bun { return &Bun{} }

func (Bun) Name() string      { return "bun" }
func (Bun) Ecosystem() string { return "npm" }

func (Bun) IsInstallCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	// bun supports `bun install` (alias `i`) and `bun add` (alias `a`).
	// `bun install` with no positionals just reads package.json — the
	// runner skips empty spec lists, so passthrough is correct.
	case "install", "i", "add", "a":
		return true
	}
	return false
}

func (Bun) ParseInstallArgs(argv []string) []PackageSpec {
	if len(argv) == 0 {
		return nil
	}
	// Strip the leading install subcommand.
	return ParseInstallArgsWith(argv[1:], bunTakesValue)
}

func bunTakesValue(flag string) bool {
	switch flag {
	// Documented bun install flags that take a value.
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
