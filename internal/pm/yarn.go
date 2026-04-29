package pm

// Yarn wraps the `yarn` CLI. It targets both classic (v1) and berry
// (v2/3/4) since both share the install-subcommand surface (`add`,
// `install`, `global add`) and the npm registry. Berry's extended
// protocols (`portal:`, `patch:`, `exec:`, `npm:`, `link:`,
// `workspace:`) are treated as non-registry passthroughs.
type Yarn struct{}

// NewYarn returns the yarn package manager.
func NewYarn() *Yarn { return &Yarn{} }

func (Yarn) Name() string      { return "yarn" }
func (Yarn) Ecosystem() string { return "npm" }

func (Yarn) IsInstallCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "add", "install":
		return true
	case "global":
		// `yarn global add foo` (yarn classic only)
		return len(argv) >= 2 && argv[1] == "add"
	}
	return false
}

func (Yarn) ParseInstallArgs(argv []string) []PackageSpec {
	if len(argv) == 0 {
		return nil
	}
	rest := argv[1:]
	// `yarn global add ...` — strip the extra "add" token too.
	if argv[0] == "global" && len(argv) >= 2 && argv[1] == "add" {
		rest = argv[2:]
	}
	return ParseInstallArgsWith(rest, yarnTakesValue)
}

func yarnTakesValue(flag string) bool {
	switch flag {
	// yarn classic flags that take a value.
	case "--registry",
		"--cwd",
		"--mutex",
		"--cache-folder",
		"--modules-folder",
		"--global-folder",
		"--proxy",
		"--https-proxy",
		"--network-concurrency",
		"--network-timeout",
		"--otp",
		// yarn berry flags that take a value.
		"--cached",
		"--mode":
		return true
	}
	return false
}

func (Yarn) Exec(args []string) error {
	return execPassthrough("yarn", args)
}
