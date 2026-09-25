// Stamps the git commit into `aegis --version`. Benchmark results record the
// engine version, and two builds from different commits both reported
// "aegis 0.30.0", which made their scorecards indistinguishable.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    // Outside a git checkout (a crates.io build) there is nothing to stamp.
    let suffix = match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(hash) if !hash.is_empty() => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|s| !s.is_empty());
            format!(" ({hash}{})", if dirty { "-dirty" } else { "" })
        }
        _ => String::new(),
    };
    println!("cargo:rustc-env=AEGIS_VERSION_SUFFIX={suffix}");
    if let Some(dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
    }
}
