package pm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Npm wraps the `npm` CLI.
type Npm struct{}

// NewNpm returns the npm package manager.
func NewNpm() *Npm { return &Npm{} }

func (Npm) Name() string      { return "npm" }
func (Npm) Ecosystem() string { return "npm" }

func (Npm) IsInstallCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	// Verbatim from npm: install + every documented prefix and the
	// well-known "isnt..." typo aliases npm itself accepts.
	case "install", "i", "in", "ins", "inst", "insta", "instal",
		"isnt", "isnta", "isntal", "isntall",
		"add":
		return true
	}
	return false
}

func (Npm) ParseInstallArgs(argv []string) []PackageSpec {
	if len(argv) == 0 {
		return nil
	}
	// Strip the leading install subcommand.
	return ParseInstallArgsWith(argv[1:], npmTakesValue)
}

func npmTakesValue(flag string) bool {
	switch flag {
	case "--workspace", "-w",
		"--workspaces",
		"--prefix",
		"--registry",
		"--tag",
		"--access":
		return true
	}
	return false
}

func (Npm) Exec(args []string) error {
	return execPassthrough("npm", args)
}

// execPassthrough is shared by every PM Exec. It looks up the binary,
// connects stdio, and propagates the child's exit code.
func execPassthrough(bin string, args []string) error {
	path, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("%s not found in PATH: %w", bin, err)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}
