// Package logx is a thin slog wrapper that picks a format (text vs
// JSON) and level based on the environment, then attaches the
// per-process invocation ID as a default attribute so every log line
// is correlatable with audit entries and HTTP request-IDs.
//
// Format selection:
//   - JSON when stderr isn't a TTY OR a CI marker is set ("CI" env,
//     "GITHUB_ACTIONS", etc.) — machine-readable in CI.
//   - Text otherwise — human-readable on a developer's terminal.
//
// Level: WARN by default; DEBUG when --verbose / AEGIS_LOG_LEVEL=debug.
package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format is the wire format for log output.
type Format int

const (
	FormatAuto Format = iota // pick based on TTY + CI markers
	FormatText
	FormatJSON
)

// Config configures New.
type Config struct {
	// Verbose flips the level from WARN → DEBUG. Reads AEGIS_LOG_LEVEL
	// when nil so users without --verbose can still raise the level.
	Verbose bool
	// Format selects text/JSON/auto. FormatAuto is recommended.
	Format Format
	// InvocationID is attached as a default attribute on every record.
	// Optional; when empty no attr is set.
	InvocationID string
	// Out is the writer. Defaults to os.Stderr.
	Out io.Writer
}

// New constructs a *slog.Logger per Config. Safe to call before
// flag parsing — pass an updated Config later if needed.
func New(cfg Config) *slog.Logger {
	out := cfg.Out
	if out == nil {
		out = os.Stderr
	}
	level := slog.LevelWarn
	if cfg.Verbose {
		level = slog.LevelDebug
	} else if v := strings.ToLower(os.Getenv("AEGIS_LOG_LEVEL")); v != "" {
		switch v {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}

	format := cfg.Format
	if format == FormatAuto {
		format = autoFormat(out)
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	switch format {
	case FormatJSON:
		handler = slog.NewJSONHandler(out, opts)
	default:
		handler = slog.NewTextHandler(out, opts)
	}

	logger := slog.New(handler)
	if cfg.InvocationID != "" {
		logger = logger.With("cli_invocation_id", cfg.InvocationID)
	}
	return logger
}

// SetDefault installs logger as the default slog. Convenience for
// callers that prefer slog.Info(...) over passing a logger around.
func SetDefault(l *slog.Logger) { slog.SetDefault(l) }

// autoFormat picks the format based on whether stderr looks like a
// terminal AND no CI markers are set. CI runs are always JSON so log
// shippers can parse them.
func autoFormat(w io.Writer) Format {
	if ciDetected() {
		return FormatJSON
	}
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return FormatText
		}
	}
	return FormatJSON
}

// ciDetected returns true when one of the canonical CI-marker env
// vars is set. The same list envprobe uses (kept here to avoid
// importing envprobe; logx must be deeply low-level so it can be used
// from anywhere in the dependency graph).
func ciDetected() bool {
	for _, k := range []string{
		"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"BUILDKITE", "TRAVIS", "JENKINS_URL",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}
