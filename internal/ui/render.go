// Package ui renders aegis CLI decision output.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/api"
)

// ANSI color codes. We honor NO_COLOR (https://no-color.org) and skip colors
// when stderr is not a terminal.
const (
	resetCode  = "\x1b[0m"
	dimCode    = "\x1b[2m"
	greenCode  = "\x1b[32m"
	yellowCode = "\x1b[33m"
	redCode    = "\x1b[31m"
	boldCode   = "\x1b[1m"
)

// Render writes a single decision to w. The format depends on decision.Decision:
//
//   allow  -> single dim line
//   warn   -> yellow header + reasons, install proceeds
//   block  -> red header + reasons + override hint
//   prompt -> red header + reasons (caller is responsible for the prompt itself)
func Render(w io.Writer, d *api.Decision) {
	switch d.Decision {
	case "allow":
		renderAllow(w, d)
	case "warn":
		renderWarn(w, d)
	case "block":
		renderBlock(w, d)
	case "prompt":
		renderPrompt(w, d)
	default:
		fmt.Fprintf(w, "[aegis] %s@%s — unknown decision %q (passing through)\n",
			d.Package, d.Version, d.Decision)
	}
}

func renderAllow(w io.Writer, d *api.Decision) {
	cached := ""
	if !d.Cached {
		cached = " (first time we've seen this — capturing in background)"
	}
	fmt.Fprintf(w, "%s[aegis]%s %s@%s %s%s%s\n",
		dim(w), reset(w),
		d.Package, d.Version,
		green(w)+"✓ allowed"+reset(w),
		cached,
		"")
}

func renderWarn(w io.Writer, d *api.Decision) {
	fmt.Fprintf(w, "%s[aegis]%s %s%s⚠ %s@%s — proceed with caution%s\n",
		dim(w), reset(w),
		yellow(w), bold(w),
		d.Package, d.Version,
		reset(w))
	for _, r := range d.Reasons {
		fmt.Fprintf(w, "%s[aegis]%s   %s%s%s — %s\n",
			dim(w), reset(w),
			yellow(w), r.Category, reset(w), r.Detail)
	}
}

func renderBlock(w io.Writer, d *api.Decision) {
	fmt.Fprintf(w, "%s[aegis]%s %s%s✗ %s@%s — BLOCKED (%s)%s\n",
		dim(w), reset(w),
		red(w), bold(w),
		d.Package, d.Version,
		strings.ToUpper(d.Severity),
		reset(w))
	for _, r := range d.Reasons {
		fmt.Fprintf(w, "%s[aegis]%s   %s%s%s — %s\n",
			dim(w), reset(w),
			red(w), r.Category, reset(w), r.Detail)
	}
	fmt.Fprintf(w, "%s[aegis]%s\n", dim(w), reset(w))
	fmt.Fprintf(w, "%s[aegis]%s   override: %sAEGIS_OVERRIDE=allow aegis npm install %s@%s%s\n",
		dim(w), reset(w),
		dim(w),
		d.Package, d.Version,
		reset(w))
}

func renderPrompt(w io.Writer, d *api.Decision) {
	// Same body as block — the caller is expected to follow this with an
	// interactive prompt. Step 8 wires that up; for now it behaves like
	// a softer block.
	fmt.Fprintf(w, "%s[aegis]%s %s%s⚠ %s@%s — REVIEW REQUIRED (%s)%s\n",
		dim(w), reset(w),
		red(w), bold(w),
		d.Package, d.Version,
		strings.ToUpper(d.Severity),
		reset(w))
	for _, r := range d.Reasons {
		fmt.Fprintf(w, "%s[aegis]%s   %s%s%s — %s\n",
			dim(w), reset(w),
			red(w), r.Category, reset(w), r.Detail)
	}
}

// Resolved logs a "resolved version" line for a package we're about to check.
func Resolved(w io.Writer, pkg, version string) {
	fmt.Fprintf(w, "%s[aegis]%s checking %s@%s ...\n",
		dim(w), reset(w), pkg, version)
}

// Skipped logs a non-registry passthrough.
func Skipped(w io.Writer, raw string) {
	fmt.Fprintf(w, "%s[aegis]%s passthrough: %s (non-registry, skipping check)\n",
		dim(w), reset(w), raw)
}

// APIError logs an API failure. We fail open — the install proceeds — but
// we shout about it loudly because in production this should be configurable.
func APIError(w io.Writer, pkg, version string, err error) {
	fmt.Fprintf(w, "%s[aegis]%s %s%s! could not check %s@%s: %v — passing through%s\n",
		dim(w), reset(w),
		yellow(w), bold(w),
		pkg, version, err,
		reset(w))
}

// --- color helpers ---

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isTerminal(f.Fd())
}

func wrap(w io.Writer, code string) string {
	if useColor(w) {
		return code
	}
	return ""
}

func reset(w io.Writer) string  { return wrap(w, resetCode) }
func dim(w io.Writer) string    { return wrap(w, dimCode) }
func green(w io.Writer) string  { return wrap(w, greenCode) }
func yellow(w io.Writer) string { return wrap(w, yellowCode) }
func red(w io.Writer) string    { return wrap(w, redCode) }
func bold(w io.Writer) string   { return wrap(w, boldCode) }
