package wrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/api"
	"github.com/qwexvf/aegis/services/cli/internal/registry"
	"github.com/qwexvf/aegis/services/cli/internal/ui"
)

// Npm wraps the user's `npm` invocation. For install subcommands it parses
// the package list, resolves versions via the npm registry, calls the Aegis
// API for a decision, renders allow/warn/block UX, and either proceeds to
// real npm or aborts with a non-zero exit.
func Npm(args []string) error {
	if len(args) > 0 && IsInstallSubcommand(args) {
		blocked, err := runInstall(args)
		if err != nil {
			return err
		}
		if blocked {
			// A blocking decision aborts before npm runs. Exit 1 so the
			// shell sees the install as failed (npm-style).
			os.Exit(1)
		}
	}
	return execRealNpm(args)
}

// runInstall returns blocked=true if any package was blocked (or
// review-required without an allow override).
func runInstall(args []string) (blocked bool, err error) {
	specs := ParseInstallArgs(args[1:])
	if len(specs) == 0 {
		// `npm install` with no positional args installs from package.json.
		// Per-package check isn't applicable here; pass through silently.
		return false, nil
	}

	override := os.Getenv("AEGIS_OVERRIDE") == "allow"

	regClient := registry.New()
	apiClient := api.New()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, spec := range specs {
		if spec.NonRegistry {
			ui.Skipped(os.Stderr, spec.Raw)
			continue
		}

		// Exact pins skip the registry round-trip — we already know the
		// version. Ranges (^4, ~1.2.3), tags (latest), and unset version
		// fall through to resolution.
		var resolved string
		if spec.IsExactVersion() {
			resolved = spec.Version
		} else {
			r, err := regClient.Resolve(ctx, spec.Name, spec.Version)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[aegis] could not resolve %s: %v (passthrough)\n", spec.Raw, err)
				continue
			}
			resolved = r
		}

		ui.Resolved(os.Stderr, spec.Name, resolved)

		decision, err := apiClient.Check(ctx, "npm", spec.Name, resolved)
		if err != nil {
			ui.APIError(os.Stderr, spec.Name, resolved, err)
			continue
		}

		ui.Render(os.Stderr, decision)

		switch decision.Decision {
		case "block", "prompt":
			if override {
				fmt.Fprintln(os.Stderr, "[aegis]   AEGIS_OVERRIDE=allow set — proceeding (audited)")
				continue
			}
			blocked = true
		}
	}
	return blocked, nil
}

func execRealNpm(args []string) error {
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return fmt.Errorf("npm not found in PATH: %w", err)
	}

	cmd := exec.Command(npmPath, args...)
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
