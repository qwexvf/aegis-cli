// Package pmwrapper bridges raw `npm`/`bun`/`yarn`/`pnpm` invocations
// into typed domain values the use case can reason about. Each PM
// implementation parses argv, classifies install vs. passthrough, and
// hands off to the underlying binary via Exec.
//
// pmwrapper sits in infra: it depends on the domain layer (for
// PackageSpec / Ecosystem) but is itself an adapter — it never reaches
// into usecase or domain.policy.
package pmwrapper

import (
	"context"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// PackageManager describes a single CLI tool the gate wraps.
type PackageManager interface {
	// Name is the canonical CLI name ("npm", "bun", "yarn", "pnpm").
	Name() string
	// Ecosystem is the registry universe this PM reads from.
	Ecosystem() domain.Ecosystem
	// InstallVerb is the canonical install verb shown in override hints
	// ("install" for npm, "add" for the others).
	InstallVerb() string
	// IsInstallCommand returns true when argv represents an install/add
	// invocation that should be gated.
	IsInstallCommand(argv []string) bool
	// ParseInstallArgs extracts package specs from the install argv.
	// argv is the FULL install argv including the leading subcommand
	// token(s) — implementations strip what they need.
	ParseInstallArgs(argv []string) []SpecToken
	// Exec delegates to the real package-manager binary with the
	// original argv. The ctx propagates Ctrl+C / SIGTERM into the
	// child process via os.Kill on cancel — `npm install` mid-flight
	// stops cleanly instead of orphaning the child.
	Exec(ctx context.Context, args []string) error
}

// SpecsToDomain converts argv-parser tokens into typed domain values
// stamped with the given ecosystem. The interface layer calls this
// before handing the result to usecase.InstallGate.
func SpecsToDomain(eco domain.Ecosystem, toks []SpecToken) []domain.PackageSpec {
	out := make([]domain.PackageSpec, len(toks))
	for i, t := range toks {
		out[i] = domain.PackageSpec{
			Ecosystem:   eco,
			Name:        t.Name,
			Version:     t.Version,
			Raw:         t.Raw,
			NonRegistry: t.NonRegistry,
		}
	}
	return out
}

// SpecToken is one parsed install target. It is the boundary type
// between argv parsing (here) and domain.PackageSpec — adapters lift
// SpecToken into a domain.PackageSpec by stamping the ecosystem.
type SpecToken struct {
	Name        string
	Version     string
	Raw         string
	NonRegistry bool
}

// parseSpec splits an install token into name+version.
func parseSpec(token string) SpecToken {
	tok := SpecToken{Raw: token}

	if isNonRegistry(token) {
		tok.NonRegistry = true
		return tok
	}

	if strings.HasPrefix(token, "@") {
		rest := token[1:]
		if before, after, ok := strings.Cut(rest, "@"); ok {
			tok.Name = "@" + before
			tok.Version = after
		} else {
			tok.Name = token
		}
		return tok
	}

	if idx := strings.Index(token, "@"); idx > 0 {
		tok.Name = token[:idx]
		tok.Version = token[idx+1:]
	} else {
		tok.Name = token
	}
	return tok
}

// isNonRegistry covers prefixes/suffixes shared across npm/bun/yarn/
// pnpm: local paths, tarballs, http(s), git, github, file:, link:,
// workspace:, and yarn-berry protocols (patch:, portal:, exec:, npm:).
func isNonRegistry(token string) bool {
	switch {
	case strings.HasPrefix(token, "./"),
		strings.HasPrefix(token, "../"),
		strings.HasPrefix(token, "/"),
		strings.HasPrefix(token, "~"),
		strings.HasPrefix(token, "http://"),
		strings.HasPrefix(token, "https://"),
		strings.HasPrefix(token, "git://"),
		strings.HasPrefix(token, "git+"),
		strings.HasPrefix(token, "file:"),
		strings.HasPrefix(token, "github:"),
		strings.HasPrefix(token, "link:"),
		strings.HasPrefix(token, "workspace:"),
		strings.HasPrefix(token, "patch:"),
		strings.HasPrefix(token, "portal:"),
		strings.HasPrefix(token, "exec:"),
		strings.HasPrefix(token, "npm:"),
		strings.HasSuffix(token, ".tgz"),
		strings.HasSuffix(token, ".tar.gz"):
		return true
	}
	return false
}

// ParseInstallArgsWith walks an install argv and returns positional
// package tokens. Flags are skipped; flags that consume a separate
// value token are recognized via the per-PM takesValue predicate.
// "--flag=value" form needs no special handling — the value is glued.
func ParseInstallArgsWith(argv []string, takesValue func(flag string) bool) []SpecToken {
	out := make([]SpecToken, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			hasNext := i+1 < len(argv)
			consumesNext := takesValue != nil && takesValue(a) && hasNext && !strings.HasPrefix(argv[i+1], "-")
			if consumesNext {
				i++
			}
			continue
		}
		out = append(out, parseSpec(a))
	}
	return out
}
