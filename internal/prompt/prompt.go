// Package prompt presents a y/N question to a real human at the
// terminal. It opens /dev/tty directly so it works even when stdin is
// being fed by a pipe (the common shell case for `aegis npm install`).
package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Result reports the user's answer.
type Result int

const (
	// ResultDenied means the user declined or any non-yes input.
	ResultDenied Result = iota
	// ResultAllowed means the user explicitly typed y or yes.
	ResultAllowed
	// ResultUnavailable means we couldn't reach a TTY (CI, redirected
	// stdin, headless run). Callers should treat this as fail-safe block.
	ResultUnavailable
)

// Confirm prints `question [y/N]: ` to /dev/tty and reads one line of
// input. Returns ResultUnavailable if /dev/tty cannot be opened (CI,
// non-interactive), in which case the caller should fail safe.
func Confirm(question string) Result {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ResultUnavailable
	}
	defer tty.Close()

	fmt.Fprintf(tty, "%s [y/N]: ", question)

	r := bufio.NewReader(tty)
	line, err := r.ReadString('\n')
	if err != nil {
		return ResultUnavailable
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return ResultAllowed
	default:
		return ResultDenied
	}
}
