// Package ttyprompt satisfies usecase.Confirmer by reading a single
// y/N line from /dev/tty. We open /dev/tty directly rather than stdin
// because stdin is typically a pipe in `aegis <pm> install` flows.
package ttyprompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// Confirmer asks the user a y/N question via /dev/tty.
type Confirmer struct{}

// New returns a Confirmer.
func New() *Confirmer { return &Confirmer{} }

// Confirm implements usecase.Confirmer.
func (Confirmer) Confirm(question string) usecase.ConfirmResult {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return usecase.ConfirmUnavailable
	}
	defer tty.Close()

	fmt.Fprintf(tty, "%s [y/N]: ", question)

	r := bufio.NewReader(tty)
	line, err := r.ReadString('\n')
	if err != nil {
		return usecase.ConfirmUnavailable
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return usecase.ConfirmAllow
	default:
		return usecase.ConfirmDeny
	}
}
