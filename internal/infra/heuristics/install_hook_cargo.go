package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// DetectCargoBuildHook scans the contents of a Cargo `build.rs` file
// for the same malware shapes the npm install-hook detector
// recognises (curl|sh, base64-piped-to-shell, fetches from
// pastebin/discord/telegram, inline-eval). build.rs is Rust's
// install-time-arbitrary-code surface — it runs on `cargo build` /
// `cargo install`, so a malicious build.rs is the crates.io equivalent
// of an npm postinstall.
//
// Reuses scriptMatchesMalwarePattern: the regex set is
// language-agnostic (it matches the shell payload, not Rust syntax),
// so a Rust build.rs that calls `Command::new("sh").arg("-c")
// .arg("curl … | sh")` produces the same hit as a JS postinstall
// embedding the same string.
//
// Returns CapInstallHookSuspicious or 0.
func DetectCargoBuildHook(buildRs []byte) domain.Capability {
	if len(buildRs) == 0 {
		return 0
	}
	if scriptMatchesMalwarePattern(string(buildRs)) {
		return domain.CapInstallHookSuspicious
	}
	return 0
}
