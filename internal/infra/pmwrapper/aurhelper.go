package pmwrapper

import (
	"context"
	"regexp"
	"strings"
)

// AURHelper wraps an Arch package tool (paru / yay / pacman). Unlike
// the registry PackageManagers, AUR installs are gated on PKGBUILD
// *content* rather than a registry version lookup, so this is a
// separate, smaller surface than the PackageManager interface.
type AURHelper struct {
	name string
	// aurDefault is true for helpers (paru/yay) where a bare positional
	// arg with no operation flag means "install that package". pacman
	// has no such default — it requires an explicit -S.
	aurDefault bool
}

// NewParu / NewYay / NewPacman construct the three supported tools.
func NewParu() *AURHelper   { return &AURHelper{name: "paru", aurDefault: true} }
func NewYay() *AURHelper    { return &AURHelper{name: "yay", aurDefault: true} }
func NewPacman() *AURHelper { return &AURHelper{name: "pacman", aurDefault: false} }

// Name is the canonical CLI name.
func (h *AURHelper) Name() string { return h.name }

// syncOp matches a pacman-style sync operation token (-S, -Sy, -Syu…).
// The capital S is the sync (install) operation.
var syncOp = regexp.MustCompile(`^-[A-Za-z]*S[A-Za-z]*$`)

// IsInstallCommand reports whether argv installs one or more named
// packages (and therefore should be scanned). Upgrades with no explicit
// targets (-Syu) and search/query/remove ops are passthrough.
func (h *AURHelper) IsInstallCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	if len(h.ParseTargets(argv)) == 0 {
		return false // -Syu, or no package named → nothing to scan
	}
	hasSync := false
	for _, a := range argv {
		switch {
		case a == "-Ss" || a == "--search" || a == "-Q" || a == "-Qs" ||
			a == "-R" || a == "-Rs" || a == "-Si" || a == "-Sii":
			return false // explicit non-install op with an argument
		case syncOp.MatchString(a):
			hasSync = true
		}
	}
	if hasSync {
		return true
	}
	// paru/yay: bare `paru firefox` installs.
	return h.aurDefault
}

// ParseTargets returns the positional package names in argv (flags and
// flag-values stripped). pacman has no install flags that take a
// separate value token in normal use, so we only drop tokens that start
// with '-'.
func (h *AURHelper) ParseTargets(argv []string) []string {
	var out []string
	for _, a := range argv {
		a = strings.TrimSpace(a)
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		// local-file installs (-U) and explicit paths aren't AUR packages.
		if strings.Contains(a, "/") || strings.HasSuffix(a, ".pkg.tar.zst") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Exec delegates to the real tool with the original argv.
func (h *AURHelper) Exec(ctx context.Context, args []string) error {
	return execPassthrough(ctx, h.name, args)
}
