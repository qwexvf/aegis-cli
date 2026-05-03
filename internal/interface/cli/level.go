package cli

import "log/slog"

// LogLevel is the runtime-mutable level used by the global slog logger
// installed in cmd/aegis/main.configureLogger. Flipped to LevelDebug by
// the root command's PersistentPreRun when --verbose is passed.
//
// Lives in this package (rather than main) so root.go can reach it
// without main → cli importing back into main, and tests can subscribe
// to the same handle.
var LogLevel = new(slog.LevelVar)
