//! Reachability hot-path benchmarks: source parsing + import/used-symbol
//! extraction, the per-file work `ci`/`reach` do across a project tree.

use std::hint::black_box;

fn main() {
    divan::main();
}

/// A realistic-size JS module: many imports + many member-call uses.
fn js_source() -> Vec<u8> {
    let mut s = String::new();
    for i in 0..200 {
        s.push_str(&format!("import {{ f{i} }} from 'dep{i}';\n"));
    }
    s.push_str("const _ = require('lodash');\n");
    for i in 0..2000 {
        s.push_str(&format!("_.merge(f{}(), {{ k: {i} }});\n", i % 200));
    }
    s.into_bytes()
}

fn rust_source() -> Vec<u8> {
    let mut s = String::from("use serde_json::{from_str, to_string};\nuse tokio::sync::mpsc;\n");
    for i in 0..2000 {
        s.push_str(&format!(
            "fn f{i}() {{ let _ = from_str::<i32>(\"{i}\"); }}\n"
        ));
    }
    s.into_bytes()
}

#[divan::bench]
fn extract_imports_js(bencher: divan::Bencher) {
    let src = js_source();
    bencher.bench(|| black_box(aegis_reach::extract_imports(black_box(&src))).len());
}

#[divan::bench]
fn extract_used_symbols_js(bencher: divan::Bencher) {
    let src = js_source();
    bencher.bench(|| black_box(aegis_reach::extract_used_symbols(black_box(&src))).len());
}

#[divan::bench]
fn extract_used_symbols_rust(bencher: divan::Bencher) {
    let src = rust_source();
    bencher.bench(|| black_box(aegis_reach::extract_used_symbols_rust(black_box(&src))).len());
}
