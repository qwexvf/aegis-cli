//! Lockfile parse hot path: a large npm lockfile through `parse_file`.

use std::hint::black_box;

use aegis_lockfile::{parse_file, DirectMap};

fn main() {
    divan::main();
}

fn package_lock(n: usize) -> Vec<u8> {
    let mut pkgs = String::from("\"\": {\"name\":\"big\",\"version\":\"1.0.0\"}");
    for i in 0..n {
        pkgs.push_str(&format!(
            ",\"node_modules/pkg{i}\":{{\"version\":\"1.2.{i}\",\"resolved\":\"https://registry.npmjs.org/pkg{i}/-/pkg{i}-1.2.{i}.tgz\"}}"
        ));
    }
    format!("{{\"name\":\"big\",\"lockfileVersion\":3,\"packages\":{{{pkgs}}}}}").into_bytes()
}

#[divan::bench(args = [100, 1000, 5000])]
fn parse_package_lock(bencher: divan::Bencher, n: usize) {
    let raw = package_lock(n);
    let dm = DirectMap::new();
    bencher.bench(|| {
        black_box(parse_file(
            black_box("package-lock.json"),
            black_box(&raw),
            &dm,
        ))
        .unwrap()
    });
}
