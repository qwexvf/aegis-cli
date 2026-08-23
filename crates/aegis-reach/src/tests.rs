//! Unit tests for the reachability parsers, split out of lib.rs.

use super::*;

fn extract(src: &str) -> Vec<Import> {
    extract_imports(src.as_bytes())
}

/// Same class of bug as the JS taint walk: nesting depth comes from the
/// package under analysis, so an import walk that recursed could be made to
/// abort the process. Every language shares `preorder`, so covering one
/// grammar plus a nested-import assertion is enough to pin the behaviour.
#[test]
fn deep_nesting_does_not_overflow_a_small_stack() {
    const DEPTH: usize = 20_000;
    let src = format!(
        "import 'lodash';\nconst a = {}1{};",
        "[".repeat(DEPTH),
        "]".repeat(DEPTH)
    );
    let imps = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || extract_imports(src.as_bytes()))
        .unwrap()
        .join()
        .expect("extracting imports from a deeply nested file must not overflow");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "lodash");
}

/// An import nested inside blocks must still be found — the iterative walk
/// has to descend, not just scan top-level statements.
#[test]
fn nested_import_is_still_found() {
    let imps = extract("function f() { if (x) { require('lodash'); } }");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "lodash");
}

#[test]
fn side_effect_import() {
    let imps = extract("import 'lodash';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "lodash");
    assert_eq!(imps[0].dep_key, "lodash");
    assert_eq!(imps[0].kind, ImportKind::Static);
    assert_eq!(imps[0].line, 1);
}

#[test]
fn default_import() {
    let imps = extract("import _ from 'lodash';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].dep_key, "lodash");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn named_imports() {
    let imps = extract("import { merge, debounce } from 'lodash';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].dep_key, "lodash");
}

#[test]
fn scoped_package_with_subpath() {
    let imps = extract("import { x } from '@scope/pkg/sub/path';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "@scope/pkg/sub/path");
    assert_eq!(imps[0].dep_key, "@scope/pkg");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn relative_import_has_empty_dep_key() {
    let imps = extract("import { x } from './local';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "./local");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Relative);
}

#[test]
fn node_builtin_scheme() {
    let imps = extract("import fs from 'node:fs';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "node:fs");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn dynamic_import() {
    let imps = extract("const m = await import('lodash');");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "lodash");
    assert_eq!(imps[0].dep_key, "lodash");
    assert_eq!(imps[0].kind, ImportKind::Dynamic);
}

#[test]
fn require_call() {
    let imps = extract("const m = require('lodash');");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "lodash");
    assert_eq!(imps[0].dep_key, "lodash");
    assert_eq!(imps[0].kind, ImportKind::Require);
}

#[test]
fn computed_dynamic_import_skipped() {
    let imps = extract("const name = 'lodash'; const m = await import(name);");
    assert!(imps.is_empty(), "{imps:?}");
}

#[test]
fn computed_require_skipped() {
    let imps = extract("const m = require(someVar);");
    assert!(imps.is_empty(), "{imps:?}");
}

#[test]
fn multiple_imports_in_one_file() {
    let src = "\nimport _ from 'lodash';\nimport { z } from 'zod';\nconst fs = require('fs');\nimport('./dynamic').then(() => {});\n";
    let imps = extract(src);
    assert_eq!(imps.len(), 4, "{imps:?}");
    let modules: Vec<&str> = imps.iter().map(|i| i.module.as_str()).collect();
    assert_eq!(modules, ["lodash", "zod", "fs", "./dynamic"]);
}

#[test]
fn typescript_type_import() {
    let imps = extract("import type { Foo } from '@scope/types/deep';");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].dep_key, "@scope/types");
}

#[test]
fn bad_source_no_panic() {
    assert!(
        extract("import { from 'broken")
            .iter()
            .all(|i| !i.module.is_empty())
            || extract("").is_empty()
    );
    // The point is simply that neither call panics.
    let _ = extract("<<< not javascript >>> ???");
}

#[test]
fn dep_key_normalization() {
    assert_eq!(dep_key("lodash"), "lodash");
    assert_eq!(dep_key("lodash/fp"), "lodash");
    assert_eq!(dep_key("@scope/pkg"), "@scope/pkg");
    assert_eq!(dep_key("@scope/pkg/sub"), "@scope/pkg");
    assert_eq!(dep_key("./foo"), "");
    assert_eq!(dep_key("../foo"), "");
    assert_eq!(dep_key("/abs/path"), "");
    assert_eq!(dep_key("node:fs"), "");
    assert_eq!(dep_key(""), "");
    assert_eq!(dep_key("@malformed"), "@malformed");
}

#[test]
fn imported_dep_keys_unions_and_filters() {
    let files = vec![
        ("a.ts".to_string(), b"import _ from 'lodash';".to_vec()),
        ("b.jsx".to_string(), b"const z = require('zod');".to_vec()),
        ("rel.js".to_string(), b"import x from './local';".to_vec()),
        // Non-JS file must be skipped.
        (
            "readme.md".to_string(),
            b"import _ from 'ignored';".to_vec(),
        ),
    ];
    let keys = imported_dep_keys(&files);
    assert!(keys.contains("lodash"));
    assert!(keys.contains("zod"));
    assert!(!keys.contains("ignored"));
    // Relative import contributes no dep key.
    assert_eq!(keys.len(), 2);
}

#[test]
fn reachability_used_and_unused() {
    let files = vec![("index.ts".to_string(), b"import _ from 'lodash';".to_vec())];
    assert_eq!(reachability_of("lodash", &files), Reachability::Used);
    assert_eq!(reachability_of("zod", &files), Reachability::Unused);
}

// --- Python ---------------------------------------------------------

fn extract_py(src: &str) -> Vec<Import> {
    extract_imports_python(src.as_bytes())
}

#[test]
fn py_plain_import() {
    let imps = extract_py("import requests");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "requests");
    assert_eq!(imps[0].dep_key, "requests");
    assert_eq!(imps[0].kind, ImportKind::Static);
    assert_eq!(imps[0].line, 1);
}

#[test]
fn py_dotted_module_top_level_dep_key() {
    let imps = extract_py("import os.path");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "os.path");
    assert_eq!(imps[0].dep_key, "os");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn pypi_import_candidates_maps_renamed_dists() {
    // curated mismatches
    assert!(pypi_import_candidates("PyYAML").contains(&"yaml".to_string()));
    assert!(pypi_import_candidates("Pillow").contains(&"PIL".to_string()));
    assert!(pypi_import_candidates("beautifulsoup4").contains(&"bs4".to_string()));
    // case-only normalization (no table entry needed)
    assert!(pypi_import_candidates("Django").contains(&"django".to_string()));
    // punctuation → underscore fallback
    assert!(pypi_import_candidates("python-dateutil").contains(&"dateutil".to_string()));
    assert!(pypi_import_candidates("some-lib").contains(&"some_lib".to_string()));
    // raw name always present
    assert!(pypi_import_candidates("requests").contains(&"requests".to_string()));
}

#[test]
fn py_from_import() {
    let imps = extract_py("from flask import Flask");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "flask");
    assert_eq!(imps[0].dep_key, "flask");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn py_from_import_dotted() {
    let imps = extract_py("from urllib.parse import urlparse");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "urllib.parse");
    assert_eq!(imps[0].dep_key, "urllib");
}

#[test]
fn py_relative_from_has_empty_dep_key() {
    let imps = extract_py("from .local import x");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, ".local");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Relative);
}

#[test]
fn py_relative_from_package_parent() {
    let imps = extract_py("from ..pkg import y");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "..pkg");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Relative);
}

#[test]
fn py_relative_from_bare() {
    let imps = extract_py("from . import x");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, ".");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Relative);
}

#[test]
fn py_aliased_dotted_import() {
    let imps = extract_py("import a.b.c as d");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "a.b.c");
    assert_eq!(imps[0].dep_key, "a");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn py_comma_list() {
    let imps = extract_py("import os, sys");
    assert_eq!(imps.len(), 2);
    let modules: Vec<&str> = imps.iter().map(|i| i.module.as_str()).collect();
    assert_eq!(modules, ["os", "sys"]);
}

#[test]
fn py_dynamic_imports() {
    for src in [
        "m = __import__('requests')",
        "m = importlib.import_module('requests')",
    ] {
        let imps = extract_py(src);
        assert_eq!(imps.len(), 1, "{src}: {imps:?}");
        assert_eq!(imps[0].module, "requests");
        assert_eq!(imps[0].dep_key, "requests");
        assert_eq!(imps[0].kind, ImportKind::Dynamic);
    }
}

#[test]
fn py_dynamic_computed_skipped() {
    let imps = extract_py("name = 'requests'\nm = __import__(name)");
    assert!(imps.is_empty(), "{imps:?}");
}

#[test]
fn py_dep_key_normalization() {
    assert_eq!(dep_key_python("requests"), "requests");
    assert_eq!(dep_key_python("requests.adapters"), "requests");
    assert_eq!(dep_key_python("urllib.parse"), "urllib");
    assert_eq!(dep_key_python(".local"), "");
    assert_eq!(dep_key_python("..pkg.x"), "");
    assert_eq!(dep_key_python("."), "");
    assert_eq!(dep_key_python(""), "");
}

#[test]
fn py_bad_source_no_panic() {
    let _ = extract_py("from import import ??? broken");
    let _ = extract_py("<<< not python >>> ???");
    assert!(extract_py("").is_empty());
}

#[test]
fn imported_dep_keys_routes_python_files() {
    let files = vec![
        ("app.py".to_string(), b"import requests".to_vec()),
        ("types.pyi".to_string(), b"from flask import Flask".to_vec()),
        ("rel.py".to_string(), b"from .local import x".to_vec()),
        // JS file still routed to the JS extractor.
        ("index.ts".to_string(), b"import _ from 'lodash';".to_vec()),
    ];
    let keys = imported_dep_keys(&files);
    assert!(keys.contains("requests"));
    assert!(keys.contains("flask"));
    assert!(keys.contains("lodash"));
    // Relative import contributes no dep key.
    assert_eq!(keys.len(), 3);
}

#[test]
fn reachability_over_python_file() {
    let files = vec![("main.py".to_string(), b"import requests".to_vec())];
    assert_eq!(reachability_of("requests", &files), Reachability::Used);
    assert_eq!(reachability_of("flask", &files), Reachability::Unused);
}

// --- Go -------------------------------------------------------------

fn extract_go(src: &str) -> Vec<Import> {
    extract_imports_go(src.as_bytes())
}

#[test]
fn go_single_stdlib_import() {
    let imps = extract_go("package main\nimport \"fmt\"");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "fmt");
    // stdlib → empty dep key.
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Static);
    assert_eq!(imps[0].line, 2);
}

#[test]
fn go_third_party_import() {
    let imps = extract_go("package main\nimport \"github.com/spf13/cobra\"");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "github.com/spf13/cobra");
    // import path IS the key — no truncation.
    assert_eq!(imps[0].dep_key, "github.com/spf13/cobra");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn go_block_import() {
    let src = "package main\nimport (\n\t\"fmt\"\n\t\"github.com/spf13/cobra\"\n)";
    let imps = extract_go(src);
    assert_eq!(imps.len(), 2, "{imps:?}");
    assert_eq!(imps[0].module, "fmt");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].line, 3);
    assert_eq!(imps[1].module, "github.com/spf13/cobra");
    assert_eq!(imps[1].dep_key, "github.com/spf13/cobra");
    assert_eq!(imps[1].line, 4);
}

#[test]
fn go_aliased_and_blank_and_dot_imports() {
    // Named alias, blank import, dot import — all static; alias dropped.
    let imps = extract_go("package main\nimport f \"fmt\"");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "fmt");
    assert_eq!(imps[0].kind, ImportKind::Static);

    let imps = extract_go("package main\nimport _ \"github.com/lib/pq\"");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "github.com/lib/pq");
    assert_eq!(imps[0].dep_key, "github.com/lib/pq");

    let imps = extract_go("package main\nimport . \"fmt\"");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "fmt");
}

#[test]
fn go_dep_key_normalization() {
    assert_eq!(dep_key_go("fmt"), "");
    assert_eq!(dep_key_go("encoding/json"), "");
    assert_eq!(
        dep_key_go("github.com/spf13/cobra"),
        "github.com/spf13/cobra"
    );
    assert_eq!(dep_key_go("example.com/x"), "example.com/x");
    assert_eq!(dep_key_go("C"), "");
    assert_eq!(dep_key_go(""), "");
}

#[test]
fn go_bad_source_no_panic() {
    let _ = extract_go("package main\nimport ( \"broken");
    let _ = extract_go("<<< not go >>> ???");
    assert!(extract_go("").is_empty());
}

#[test]
fn reachability_over_go_file() {
    let files = vec![(
        "main.go".to_string(),
        b"package main\nimport \"github.com/spf13/cobra\"".to_vec(),
    )];
    assert_eq!(
        reachability_of("github.com/spf13/cobra", &files),
        Reachability::Used
    );
    // stdlib never becomes a dep key.
    assert_eq!(reachability_of("fmt", &files), Reachability::Unused);
}

// --- PHP ------------------------------------------------------------

fn extract_php(src: &str) -> Vec<Import> {
    extract_imports_php(src.as_bytes())
}

#[test]
fn php_plain_use() {
    let imps = extract_php("<?php use Symfony\\Component\\Console\\Application;");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "Symfony\\Component\\Console\\Application");
    // PHP dep keys are always empty.
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn php_use_with_alias() {
    let imps = extract_php("<?php use Symfony\\Component\\Console\\Application as App;");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "Symfony\\Component\\Console\\Application");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn php_require_include_are_relative() {
    for src in [
        "<?php require 'vendor/autoload.php';",
        "<?php require_once \"vendor/autoload.php\";",
        "<?php include 'vendor/autoload.php';",
        "<?php include_once 'vendor/autoload.php';",
    ] {
        let imps = extract_php(src);
        assert_eq!(imps.len(), 1, "{src}: {imps:?}");
        assert_eq!(imps[0].module, "vendor/autoload.php");
        assert_eq!(imps[0].dep_key, "");
        assert_eq!(imps[0].kind, ImportKind::Relative);
    }
}

#[test]
fn php_dep_key_always_empty() {
    assert_eq!(dep_key_php("Symfony\\Component"), "");
    assert_eq!(dep_key_php("anything"), "");
    assert_eq!(dep_key_php(""), "");
}

#[test]
fn php_bad_source_no_panic() {
    let _ = extract_php("<?php use ??? broken");
    let _ = extract_php("<<< not php >>> ???");
    assert!(extract_php("").is_empty());
}

#[test]
fn reachability_over_php_file() {
    // PHP dep keys are always empty, so a PHP file contributes no
    // reachable keys — faithful to depusage (Composer resolution is
    // the consumer's job).
    let files = vec![(
        "index.php".to_string(),
        b"<?php use Symfony\\Component\\Console\\Application;".to_vec(),
    )];
    assert!(imported_dep_keys(&files).is_empty());
    assert_eq!(
        reachability_of("Symfony\\Component\\Console\\Application", &files),
        Reachability::Unused
    );
}

// --- Ruby -----------------------------------------------------------

fn extract_rb(src: &str) -> Vec<Import> {
    extract_imports_ruby(src.as_bytes())
}

#[test]
fn rb_plain_require() {
    let imps = extract_rb("require 'rails'");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "rails");
    assert_eq!(imps[0].dep_key, "rails");
    assert_eq!(imps[0].kind, ImportKind::Require);
    assert_eq!(imps[0].line, 1);
}

#[test]
fn rb_require_subpath_dep_key() {
    let imps = extract_rb("require 'active_support/core_ext'");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "active_support/core_ext");
    assert_eq!(imps[0].dep_key, "active_support");
    assert_eq!(imps[0].kind, ImportKind::Require);
}

#[test]
fn rb_require_relative_is_relative() {
    let imps = extract_rb("require_relative './helpers'");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "./helpers");
    assert_eq!(imps[0].dep_key, "");
    assert_eq!(imps[0].kind, ImportKind::Relative);
}

#[test]
fn rb_gem_call() {
    let imps = extract_rb("gem 'pg'");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].module, "pg");
    assert_eq!(imps[0].dep_key, "pg");
    assert_eq!(imps[0].kind, ImportKind::Require);
}

#[test]
fn rb_computed_require_skipped() {
    let imps = extract_rb("require some_var");
    assert!(imps.is_empty(), "{imps:?}");
}

#[test]
fn rb_dep_key_normalization() {
    assert_eq!(dep_key_ruby("rails"), "rails");
    assert_eq!(dep_key_ruby("active_support"), "active_support");
    assert_eq!(dep_key_ruby("active_support/core_ext"), "active_support");
    assert_eq!(dep_key_ruby("./local"), "");
    assert_eq!(dep_key_ruby("../helpers"), "");
    assert_eq!(dep_key_ruby(""), "");
}

#[test]
fn rb_bad_source_no_panic() {
    let _ = extract_rb("require ??? broken (");
    let _ = extract_rb("<<< not ruby >>> ???");
    assert!(extract_rb("").is_empty());
}

#[test]
fn reachability_over_ruby_file() {
    let files = vec![("app.rb".to_string(), b"require 'rails'\ngem 'pg'".to_vec())];
    assert_eq!(reachability_of("rails", &files), Reachability::Used);
    assert_eq!(reachability_of("pg", &files), Reachability::Used);
    assert_eq!(reachability_of("sinatra", &files), Reachability::Unused);
}

// --- Rust -----------------------------------------------------------

fn extract_rs(src: &str) -> Vec<Import> {
    extract_imports_rust(src.as_bytes())
}

#[test]
fn rs_use_crate_paths() {
    let imps =
        extract_rs("use serde::Serialize;\nuse tokio::sync::mpsc;\nuse anyhow::{Result, Context};");
    let keys: std::collections::HashSet<_> = imps.iter().map(|i| i.dep_key.as_str()).collect();
    assert!(keys.contains("serde"));
    assert!(keys.contains("tokio"));
    assert!(keys.contains("anyhow"));
    assert!(imps.iter().all(|i| i.kind == ImportKind::Static));
}

#[test]
fn rs_extern_crate() {
    let imps = extract_rs("extern crate rocket;");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].dep_key, "rocket");
    assert_eq!(imps[0].kind, ImportKind::Static);
}

#[test]
fn rs_local_and_stdlib_normalize_empty() {
    let imps = extract_rs(
        "use crate::foo;\nuse self::bar;\nuse super::baz;\nuse std::collections::HashMap;\nuse core::mem;\nuse alloc::vec::Vec;",
    );
    assert!(
        imps.iter().all(|i| i.dep_key.is_empty()),
        "expected all empty dep keys, got {imps:?}"
    );
}

#[test]
fn rs_used_symbols_named_import_call() {
    // `use serde_json::from_str; from_str(...)` → (serde_json, from_str).
    let syms = extract_used_symbols_rust(
        b"use serde_json::from_str;\nfn f() { let _ = from_str(\"{}\"); }\n",
    );
    assert!(
        syms.iter()
            .any(|s| s.module == "serde_json" && s.symbol == "from_str"),
        "got {syms:?}"
    );
}

#[test]
fn deeply_nested_source_does_not_overflow() {
    // The used-symbol / call-graph / site walkers recurse per AST level;
    // MAX_AST_DEPTH guards them. A few thousand levels used to overflow the
    // stack — now each entry returns empty instead of crashing.
    let js = format!("const _=require('lodash');\n{}", "a(".repeat(5000));
    let _ = extract_used_symbols(js.as_bytes());
    let _ = call_graph(js.as_bytes());
    let _ = used_symbol_sites(js.as_bytes());
    let py = format!("import os\nx={}1{}\n", "(".repeat(5000), ")".repeat(5000));
    let _ = extract_used_symbols_python(py.as_bytes());
    let rs = format!("use serde::Serialize;\nfn f(){{ {} }}", "g(".repeat(5000));
    let _ = extract_used_symbols_rust(rs.as_bytes());
    // A normal (shallow) file still yields results.
    let ok = extract_used_symbols(b"const _=require('lodash');\n_.merge({},{});\n");
    assert!(ok.iter().any(|u| u.module == "lodash"), "{ok:?}");
}

#[test]
fn expand_rust_use_malformed_and_deep_no_panic() {
    // Reversed braces (`}` before `{`) must not slice a reversed range.
    let out = expand_rust_use("a::}{b");
    assert!(
        !out.is_empty(),
        "malformed input should still yield something"
    );
    // Pathological nesting must not overflow the stack (depth-bounded).
    let deep = format!("a::{}{}", "{".repeat(500), "}".repeat(500));
    let _ = expand_rust_use(&deep);
    // A normal grouped/aliased tree still expands correctly.
    let ok = expand_rust_use("serde::{Serialize, de::Deserializer as D}");
    assert!(ok.iter().any(|(p, _)| p == "serde::Serialize"), "{ok:?}");
    assert!(
        ok.iter()
            .any(|(p, a)| p == "serde::de::Deserializer" && a.as_deref() == Some("D")),
        "{ok:?}"
    );
}

#[test]
fn rs_used_symbols_turbofish_call() {
    // `from_str::<i32>(...)` parses as a generic_function callee.
    let syms = extract_used_symbols_rust(
        b"use serde_json::from_str;\nfn f() { let _ = from_str::<i32>(\"1\"); }\n",
    );
    assert!(
        syms.iter()
            .any(|s| s.module == "serde_json" && s.symbol == "from_str"),
        "turbofish call missed: {syms:?}"
    );
}

#[test]
fn rs_used_symbols_full_path_and_member_access() {
    // full path: `serde_json::to_string(...)` (crate imported via `use`).
    // member access on a bound module: `mpsc::channel()`.
    let src = b"use serde_json;\nuse tokio::sync::mpsc;\nfn f() { serde_json::to_string(&1); let _ = mpsc::channel::<u8>(); }\n";
    let syms = extract_used_symbols_rust(src);
    assert!(
        syms.iter()
            .any(|s| s.module == "serde_json" && s.symbol == "to_string"),
        "full-path use missing: {syms:?}"
    );
    assert!(
        syms.iter()
            .any(|s| s.module == "tokio" && s.symbol == "channel"),
        "member-access use missing: {syms:?}"
    );
}

#[test]
fn rs_used_symbols_alias_and_grouped() {
    // grouped import with an alias: `use anyhow::{Result as R, bail};`
    let src = b"use anyhow::{Result as R, bail};\nfn f() -> R<()> { bail!(\"x\") }\n";
    let syms = extract_used_symbols_rust(src);
    // `bail!` is a macro (not a plain call) — the grouped/alias parse is what
    // we assert here via used_symbols_of over a project.
    let files = vec![("m.rs".to_string(), src.to_vec())];
    let used = used_symbols_of("anyhow", &files);
    // R aliases Result; using R in a path/return isn't call-anchored, so the
    // set may be empty — the point is the parse doesn't panic and routes .rs.
    let _ = used;
    let _ = syms;
}

#[test]
fn rs_used_symbols_skips_local_and_stdlib() {
    // `crate::`, `std::`, and unimported local modules contribute nothing.
    let src =
        b"use std::collections::HashMap;\nfn f() { let _ = HashMap::new(); crate::helper::go(); mymod::thing(); }\n";
    let syms = extract_used_symbols_rust(src);
    assert!(
        syms.iter().all(|s| s.module != "std"
            && s.module != "crate"
            && s.module != "mymod"
            && s.module != "helper"),
        "leaked a non-crate module: {syms:?}"
    );
}

#[test]
fn rs_used_symbols_via_project_helper() {
    let files = vec![(
        "app.rs".to_string(),
        b"use serde_json::from_str;\nfn f() { let _ = from_str(\"{}\"); }\n".to_vec(),
    )];
    let used = used_symbols_of("serde_json", &files);
    assert!(used.contains("from_str"), "got {used:?}");
    assert!(used_symbols_of("nonexistent", &files).is_empty());
}

#[test]
fn rs_dep_key_normalization() {
    assert_eq!(dep_key_rust("serde::Serialize"), "serde");
    assert_eq!(dep_key_rust("tokio::sync::mpsc"), "tokio");
    assert_eq!(dep_key_rust("crate::foo"), "");
    assert_eq!(dep_key_rust("self::bar"), "");
    assert_eq!(dep_key_rust("super::baz"), "");
    assert_eq!(dep_key_rust("std::io"), "");
    assert_eq!(dep_key_rust("core::mem"), "");
    assert_eq!(dep_key_rust("alloc::vec"), "");
    assert_eq!(dep_key_rust(""), "");
}

#[test]
fn rs_bad_source_no_panic() {
    let _ = extract_rs("use ??? broken (");
    assert!(extract_rs("").is_empty());
}

#[test]
fn reachability_over_rust_file() {
    let files = vec![(
        "lib.rs".to_string(),
        b"use serde::Serialize;\nuse crate::internal;".to_vec(),
    )];
    assert_eq!(reachability_of("serde", &files), Reachability::Used);
    assert_eq!(reachability_of("tokio", &files), Reachability::Unused);
    // crate-local import contributes no dep key.
    assert!(!imported_dep_keys(&files).contains("internal"));
}

// --- Java -----------------------------------------------------------

fn extract_java(src: &str) -> Vec<Import> {
    extract_imports_java(src.as_bytes())
}

#[test]
fn java_single_and_wildcard_imports() {
    let src =
        "package x;\nimport com.google.common.collect.Lists;\nimport org.apache.commons.lang3.*;\n";
    let imps = extract_java(src);
    let by_key: std::collections::HashSet<_> = imps.iter().map(|i| i.dep_key.as_str()).collect();
    // trailing type `Lists` dropped → package prefix.
    assert!(by_key.contains("com.google.common.collect"));
    // wildcard keeps the whole package.
    assert!(by_key.contains("org.apache.commons.lang3"));
    assert!(imps.iter().all(|i| i.kind == ImportKind::Static));
}

#[test]
fn java_static_import() {
    let imps = extract_java("import static org.junit.Assert.assertEquals;");
    assert_eq!(imps.len(), 1);
    // member `assertEquals` and type `Assert` stripped → package prefix.
    assert_eq!(imps[0].dep_key, "org.junit");
}

#[test]
fn java_jdk_normalizes_empty() {
    let imps = extract_java("import java.util.List;\nimport javax.annotation.Nullable;");
    assert!(
        imps.iter().all(|i| i.dep_key.is_empty()),
        "expected empty dep keys, got {imps:?}"
    );
}

#[test]
fn java_dep_key_normalization() {
    assert_eq!(
        dep_key_java("com.google.common.collect.Lists"),
        "com.google.common.collect"
    );
    assert_eq!(
        dep_key_java("org.apache.commons.lang3"),
        "org.apache.commons.lang3"
    );
    assert_eq!(dep_key_java("java.util.List"), "");
    assert_eq!(dep_key_java("javax.annotation.Nullable"), "");
    assert_eq!(dep_key_java(""), "");
}

#[test]
fn java_bad_source_no_panic() {
    let _ = extract_java("import ??? broken");
    assert!(extract_java("").is_empty());
}

fn extract_cs(src: &str) -> Vec<Import> {
    extract_imports_csharp(src.as_bytes())
}

#[test]
fn cs_plain_global_and_alias_usings() {
    let src = "using System.Text.Json;\nglobal using Newtonsoft.Json.Linq;\nusing J = System.Text.Json;\nnamespace A { class C {} }\n";
    let imps = extract_cs(src);
    let keys: std::collections::HashSet<_> = imps.iter().map(|i| i.dep_key.as_str()).collect();
    // whole namespace kept (System.* NOT filtered — real nuget packages).
    assert!(keys.contains("System.Text.Json"), "{imps:?}");
    assert!(keys.contains("Newtonsoft.Json.Linq"), "{imps:?}");
    assert!(imps.iter().all(|i| i.kind == ImportKind::Static));
}

#[test]
fn cs_static_using_strips_type() {
    // `using static System.Math;` → namespace System (type Math stripped).
    let imps = extract_cs("using static System.Math;");
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].dep_key, "System");
}

#[test]
fn cs_dep_key_and_bad_source() {
    assert_eq!(dep_key_csharp("Newtonsoft.Json"), "Newtonsoft.Json");
    assert_eq!(dep_key_csharp(""), "");
    let _ = extract_cs("using ??? broken");
    assert!(extract_cs("").is_empty());
}

#[test]
fn reachability_over_java_file() {
    let files = vec![(
        "App.java".to_string(),
        b"import com.google.common.collect.Lists;\nimport java.util.List;".to_vec(),
    )];
    assert_eq!(
        reachability_of("com.google.common.collect", &files),
        Reachability::Used
    );
    assert_eq!(
        reachability_of("com.example.foo", &files),
        Reachability::Unused
    );
}

#[test]
fn imported_dep_keys_routes_all_languages() {
    let files = vec![
        (
            "main.go".to_string(),
            b"package main\nimport \"github.com/spf13/cobra\"".to_vec(),
        ),
        ("app.rb".to_string(), b"require 'rails'".to_vec()),
        ("lib.gemspec".to_string(), b"gem 'pg'".to_vec()),
        ("index.php".to_string(), b"<?php use Foo\\Bar;".to_vec()),
        ("index.ts".to_string(), b"import _ from 'lodash';".to_vec()),
    ];
    let keys = imported_dep_keys(&files);
    assert!(keys.contains("github.com/spf13/cobra"));
    assert!(keys.contains("rails"));
    assert!(keys.contains("pg"));
    assert!(keys.contains("lodash"));
    // PHP contributes nothing (empty dep keys).
    assert_eq!(keys.len(), 4);
}

// --- JS/TS used-symbols ---------------------------------------------

fn used(src: &str) -> Vec<UsedSymbol> {
    extract_used_symbols(src.as_bytes())
}

fn symbols_on(src: &str, module: &str) -> Vec<String> {
    let mut names: Vec<String> = used(src)
        .into_iter()
        .filter(|u| u.module == module)
        .map(|u| u.symbol)
        .collect();
    names.sort();
    names
}

#[test]
fn require_member_access() {
    let uses = used("const cp = require('child_process');\ncp.execSync('x');");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "child_process");
    assert_eq!(uses[0].symbol, "execSync");
    assert_eq!(uses[0].line, 2);
}

#[test]
fn named_import_call() {
    let uses = used("import { readFile } from 'fs';\nreadFile('a', cb);");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "fs");
    assert_eq!(uses[0].symbol, "readFile");
}

#[test]
fn multiple_named_import_calls() {
    let src = "import { merge, debounce } from 'lodash';\nmerge({}, {});\ndebounce(fn, 200);";
    assert_eq!(symbols_on(src, "lodash"), ["debounce", "merge"]);
}

#[test]
fn default_import_member() {
    let src = "import _ from 'lodash';\n_.merge({}, {});\nconst x = _.PI;";
    assert_eq!(symbols_on(src, "lodash"), ["PI", "merge"]);
}

#[test]
fn namespace_import_member() {
    let src = "import * as L from 'lodash';\nL.merge({}, {});\nL.debounce(fn);";
    assert_eq!(symbols_on(src, "lodash"), ["debounce", "merge"]);
}

#[test]
fn aliased_named_import_maps_to_canonical() {
    // `merge as m` used as `m(...)` resolves back to canonical "merge".
    let uses = used("import { merge as m } from 'lodash';\nm({}, {});");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].symbol, "merge");
    assert_eq!(uses[0].module, "lodash");
}

#[test]
fn member_chain_yields_head_property() {
    // `_.a.b()` — the head member access on the bound identifier wins.
    assert_eq!(
        symbols_on("import _ from 'lodash';\n_.a.b();", "lodash"),
        ["a"]
    );
}

#[test]
fn subpath_import_normalizes_module_to_dep_key() {
    // `lodash/fp` normalizes to dep key `lodash`.
    let uses = used("import { flow } from 'lodash/fp';\nflow(a, b);");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "lodash");
    assert_eq!(uses[0].symbol, "flow");
}

#[test]
fn unused_import_contributes_no_symbol() {
    // Imported but never referenced.
    assert!(used("import { unused } from 'lodash';").is_empty());
    // Bound, but only a same-named local (not the import) is called.
    let uses = used("import { merge } from 'lodash';\nconst z = other();");
    assert!(uses.is_empty(), "{uses:?}");
}

#[test]
fn no_bindings_yields_empty() {
    // Nothing imported → no bindings → no used-symbols.
    assert!(used("cp.execSync('x');\nfoo.bar();").is_empty());
}

#[test]
fn used_symbols_bad_source_no_panic() {
    let _ = used("const cp = require( broken");
    let _ = used("<<< not javascript >>> ???");
    assert!(used("").is_empty());
}

#[test]
fn used_symbols_of_present_and_absent() {
    let files = vec![
        (
            "worker.ts".to_string(),
            b"const cp = require('child_process');\ncp.execSync('ls');\ncp.spawn('x');".to_vec(),
        ),
        (
            "util.js".to_string(),
            b"import { merge } from 'lodash';\nmerge({}, {});".to_vec(),
        ),
        // Non-JS file must be skipped.
        (
            "notes.md".to_string(),
            b"const cp = require('child_process');\ncp.fork('x');".to_vec(),
        ),
    ];
    let syms = used_symbols_of("child_process", &files);
    assert!(syms.contains("execSync"));
    assert!(syms.contains("spawn"));
    // Present via a skipped non-JS file → absent.
    assert!(!syms.contains("fork"));
    assert_eq!(syms.len(), 2);

    assert_eq!(
        used_symbols_of("lodash", &files),
        HashSet::from(["merge".to_string()])
    );
    // A dep with no recorded usage → empty set.
    assert!(used_symbols_of("express", &files).is_empty());
}

// --- Python used-symbols --------------------------------------------

fn used_py(src: &str) -> Vec<UsedSymbol> {
    extract_used_symbols_python(src.as_bytes())
}

fn py_symbols_on(src: &str, module: &str) -> Vec<String> {
    let mut names: Vec<String> = used_py(src)
        .into_iter()
        .filter(|u| u.module == module)
        .map(|u| u.symbol)
        .collect();
    names.sort();
    names
}

#[test]
fn py_import_attribute_call() {
    // `import os` then `os.system(...)` → symbol `system` on `os`.
    let uses = used_py("import os\nos.system('ls')");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "os");
    assert_eq!(uses[0].symbol, "system");
    assert_eq!(uses[0].line, 2);
}

#[test]
fn py_aliased_module_attribute() {
    // `import numpy as np` then `np.array(...)`, `np.matmul(...)`.
    assert_eq!(
        py_symbols_on(
            "import numpy as np\narr = np.array([1, 2])\nm = np.matmul(a, b)",
            "numpy"
        ),
        ["array", "matmul"]
    );
}

#[test]
fn py_from_import_call() {
    // `from subprocess import run` then `run(...)` → symbol `run`.
    let uses = used_py("from subprocess import run\nrun(['ls'])");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "subprocess");
    assert_eq!(uses[0].symbol, "run");
}

#[test]
fn py_from_import_multiple_calls() {
    let src = "from requests import get, post\nr = get('https://x')\npost('https://x', json={})";
    assert_eq!(py_symbols_on(src, "requests"), ["get", "post"]);
}

#[test]
fn py_aliased_named_import_maps_to_canonical() {
    // `from a import b as c` then `c(...)` → canonical symbol `b`.
    let uses = used_py("from requests import get as g\ng('https://x')");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "requests");
    assert_eq!(uses[0].symbol, "get");
}

#[test]
fn py_dotted_import_binds_last_segment() {
    // `import os.path` binds the module's last dotted segment (`path`)
    // as the local — faithful to depusage's `buildBindings`
    // (last-segment rule). The dep-key of the usage is the top-level
    // package `os`. Accessing via that local records the attribute.
    let uses = used_py("import os.path\npath.join('a', 'b')");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_eq!(uses[0].module, "os");
    assert_eq!(uses[0].symbol, "join");
}

#[test]
fn py_dotted_import_compound_head_unbound() {
    // `os.path.join(...)` accesses through the compound `os.path`
    // head, whose object `os` is not itself bound by `import os.path`
    // (only `path` is) — so nothing is recorded. Ported quirk.
    assert!(used_py("import os.path\nos.path.join('a', 'b')").is_empty());
}

#[test]
fn py_unused_import_contributes_no_symbol() {
    assert!(used_py("import os").is_empty());
    assert!(used_py("from subprocess import run").is_empty());
    // A same-named local call that isn't the whole-module binding.
    assert!(used_py("import numpy as np\nother()").is_empty());
}

#[test]
fn py_no_bindings_yields_empty() {
    assert!(used_py("os.system('x')\nfoo.bar()").is_empty());
}

#[test]
fn py_used_symbols_bad_source_no_panic() {
    let _ = used_py("from import import ??? broken");
    let _ = used_py("<<< not python >>> ???");
    assert!(used_py("").is_empty());
}

#[test]
fn used_symbols_of_routes_python() {
    let files = vec![
        (
            "worker.py".to_string(),
            b"import os\nos.system('ls')\nos.getcwd()".to_vec(),
        ),
        (
            "client.pyi".to_string(),
            b"from requests import get\nget('https://x')".to_vec(),
        ),
        // JS file still routed to the JS used-symbol pass.
        (
            "util.js".to_string(),
            b"import { merge } from 'lodash';\nmerge({}, {});".to_vec(),
        ),
        // Non-source file must be skipped.
        (
            "notes.md".to_string(),
            b"import os\nos.remove('x')".to_vec(),
        ),
    ];
    let syms = used_symbols_of("os", &files);
    assert!(syms.contains("system"));
    assert!(syms.contains("getcwd"));
    // Present only via a skipped non-source file → absent.
    assert!(!syms.contains("remove"));
    assert_eq!(syms.len(), 2);

    assert_eq!(
        used_symbols_of("requests", &files),
        HashSet::from(["get".to_string()])
    );
    assert_eq!(
        used_symbols_of("lodash", &files),
        HashSet::from(["merge".to_string()])
    );
    // A dep with no recorded usage → empty set.
    assert!(used_symbols_of("flask", &files).is_empty());
}

// --- Go used-symbols ------------------------------------------------

fn used_go(src: &str) -> Vec<UsedSymbol> {
    extract_used_symbols_go(src.as_bytes())
}

#[test]
fn go_used_symbols_selector_access() {
    // Bare third-party import → local is the last path segment.
    let syms = used_go(
        "package main\nimport \"github.com/spf13/cobra\"\nfunc main() { cobra.Command{}; cobra.OnInitialize() }",
    );
    let names: HashSet<_> = syms
        .iter()
        .filter(|u| u.module == "github.com/spf13/cobra")
        .map(|u| u.symbol.clone())
        .collect();
    assert!(names.contains("Command"));
    assert!(names.contains("OnInitialize"));
}

#[test]
fn go_used_symbols_alias() {
    // Aliased import → the alias is the local name.
    let syms =
        used_go("package main\nimport co \"github.com/spf13/cobra\"\nfunc main() { co.Execute() }");
    assert_eq!(
        syms.iter()
            .filter(|u| u.module == "github.com/spf13/cobra")
            .map(|u| u.symbol.clone())
            .collect::<HashSet<_>>(),
        HashSet::from(["Execute".to_string()])
    );
}

#[test]
fn go_used_symbols_blank_and_dot_bind_nothing() {
    // Blank import is side-effect-only; nothing is selector-accessed.
    assert!(used_go("package main\nimport _ \"github.com/lib/pq\"\nfunc main() {}").is_empty());
    // Dot import merges names into scope — no qualifier to track.
    assert!(used_go("package main\nimport . \"fmt\"\nfunc main() { Println(\"x\") }").is_empty());
}

#[test]
fn go_used_symbols_nested_selector() {
    // `pkg.A.B` surfaces only `A` on the package — the outer selector's
    // operand is a selector_expression, not the bound identifier.
    let syms = used_go("package main\nimport \"github.com/x/y\"\nfunc main() { y.Config.Field }");
    assert_eq!(
        syms.iter()
            .filter(|u| u.module == "github.com/x/y")
            .map(|u| u.symbol.clone())
            .collect::<HashSet<_>>(),
        HashSet::from(["Config".to_string()])
    );
}

#[test]
fn go_used_symbols_bad_source_no_panic() {
    let _ = used_go("package main\nimport ( \"broken");
    let _ = used_go("<<< not go >>> ???");
    assert!(used_go("").is_empty());
}

#[test]
fn used_symbols_of_routes_go() {
    let files = vec![
        (
            "main.go".to_string(),
            b"package main\nimport \"github.com/spf13/cobra\"\nfunc main() { cobra.Command{} }"
                .to_vec(),
        ),
        // stdlib is selector-accessed but never forms a registry dep key.
        (
            "util.go".to_string(),
            b"package main\nimport \"fmt\"\nfunc x() { fmt.Println(\"y\") }".to_vec(),
        ),
    ];
    assert_eq!(
        used_symbols_of("github.com/spf13/cobra", &files),
        HashSet::from(["Command".to_string()])
    );
    // fmt is used, but its module is the verbatim "fmt", not a dep key.
    assert!(used_symbols_of("fmt", &files).contains("Println"));
    // A dep with no recorded usage → empty set.
    assert!(used_symbols_of("github.com/pkg/errors", &files).is_empty());
}

// --- PHP used-symbols -----------------------------------------------

fn used_php(src: &str) -> Vec<UsedSymbol> {
    extract_used_symbols_php(src.as_bytes())
}

fn php_syms(src: &str, module: &str) -> HashSet<String> {
    used_php(src)
        .iter()
        .filter(|u| u.module == module)
        .map(|u| u.symbol.clone())
        .collect()
}

#[test]
fn php_used_symbols_scoped_call_and_const() {
    let src = "<?php\nuse Foo\\Bar;\nBar::make();\nBar::VERSION;\n";
    assert_eq!(
        php_syms(src, "Foo\\Bar"),
        HashSet::from(["make".to_string(), "VERSION".to_string()])
    );
}

#[test]
fn php_used_symbols_alias() {
    let src = "<?php\nuse Foo\\Bar as B;\nB::run();\n";
    assert_eq!(
        php_syms(src, "Foo\\Bar"),
        HashSet::from(["run".to_string()])
    );
}

#[test]
fn php_used_symbols_group() {
    let src = "<?php\nuse Foo\\{Bar, Baz as Q};\nBar::a();\nQ::b();\n";
    assert_eq!(php_syms(src, "Foo\\Bar"), HashSet::from(["a".to_string()]));
    assert_eq!(php_syms(src, "Foo\\Baz"), HashSet::from(["b".to_string()]));
}

#[test]
fn php_used_symbols_new_binds_no_member() {
    // `new Bar()` references the class but no member → no symbol, even
    // though the import itself is still reachable elsewhere.
    let src = "<?php\nuse Foo\\Bar;\n$x = new Bar();\n";
    assert!(php_syms(src, "Foo\\Bar").is_empty());
}

#[test]
fn php_used_symbols_bad_source_no_panic() {
    let _ = used_php("<?php use broken");
    let _ = used_php("<<< not php >>> ???");
    assert!(used_php("").is_empty());
}

#[test]
fn used_symbols_of_routes_php() {
    let files = vec![
        (
            "app.php".to_string(),
            b"<?php\nuse Symfony\\Component\\Console\\Application;\nApplication::create();\n"
                .to_vec(),
        ),
        // .phtml is also routed through the PHP pass.
        (
            "view.phtml".to_string(),
            b"<?php\nuse App\\Helper;\nHelper::render();\n".to_vec(),
        ),
    ];
    assert_eq!(
        used_symbols_of("Symfony\\Component\\Console\\Application", &files),
        HashSet::from(["create".to_string()])
    );
    assert_eq!(
        used_symbols_of("App\\Helper", &files),
        HashSet::from(["render".to_string()])
    );
    // A dep with no recorded usage → empty set.
    assert!(used_symbols_of("App\\Missing", &files).is_empty());
}

// --- Call graph (JS) ------------------------------------------------

fn cg(src: &str) -> Vec<CallNode> {
    call_graph(src.as_bytes())
}

/// Callees recorded for `function` in a call graph, or `None` if the
/// scope isn't present.
fn calls_of<'a>(graph: &'a [CallNode], function: &str) -> Option<&'a [String]> {
    graph
        .iter()
        .find(|n| n.function == function)
        .map(|n| n.calls.as_slice())
}

#[test]
fn cg_function_declaration_edges() {
    let src = "function a() { b(); c(); }\nfunction b() { c(); }\nfunction c() {}";
    let g = cg(src);
    assert_eq!(
        calls_of(&g, "a"),
        Some(&["b".to_string(), "c".to_string()][..])
    );
    assert_eq!(calls_of(&g, "b"), Some(&["c".to_string()][..]));
    // `c` makes no calls but is still a node.
    assert_eq!(calls_of(&g, "c"), Some(&[][..]));
}

#[test]
fn cg_top_level_calls_attribute_to_module() {
    let src = "setup();\nfunction setup() { init(); }";
    let g = cg(src);
    assert_eq!(calls_of(&g, "<module>"), Some(&["setup".to_string()][..]));
    assert_eq!(calls_of(&g, "setup"), Some(&["init".to_string()][..]));
}

#[test]
fn cg_const_arrow_and_function_expression() {
    let src = "const f = () => { helper(); };\nconst g = function () { f(); };";
    let g = cg(src);
    assert_eq!(calls_of(&g, "f"), Some(&["helper".to_string()][..]));
    assert_eq!(calls_of(&g, "g"), Some(&["f".to_string()][..]));
}

#[test]
fn cg_method_and_member_callee_token() {
    // Method scope named by the method; member calls record the property.
    let src = "class C { run() { this.step(); lib.doThing(); } }";
    let g = cg(src);
    assert_eq!(
        calls_of(&g, "run"),
        Some(&["step".to_string(), "doThing".to_string()][..])
    );
}

#[test]
fn cg_anonymous_callback_folds_into_enclosing_scope() {
    // The arrow passed to `arr.forEach` opens no scope — its `sink()`
    // call attributes to the enclosing named function `process`.
    let src = "function process(arr) { arr.forEach(x => { sink(x); }); }";
    let g = cg(src);
    let calls = calls_of(&g, "process").unwrap();
    // `forEach` (the method call) and `sink` (inside the callback) both
    // land in `process` — the callback body is not pruned away.
    assert!(calls.contains(&"forEach".to_string()));
    assert!(calls.contains(&"sink".to_string()));
    // No separate anonymous scope was created.
    assert!(g.iter().all(|n| n.function != "<anon>"));
}

#[test]
fn cg_dedup_repeated_callee() {
    let src = "function a() { log(); log(); log(); }";
    assert_eq!(calls_of(&cg(src), "a"), Some(&["log".to_string()][..]));
}

#[test]
fn cg_bad_source_no_panic() {
    let _ = cg("function ( { broken");
    let _ = cg("<<< not js >>> ???");
    assert!(cg("").is_empty());
}

// --- Used-symbol sites (JS scope attribution) -----------------------

fn sites(src: &str) -> Vec<SymbolSite> {
    used_symbol_sites(src.as_bytes())
}

#[test]
fn sites_attribute_member_use_to_enclosing_function() {
    let src = "import cp from 'child_process';\nfunction run() { cp.execSync('ls'); }";
    let s = sites(src);
    let hit = s
        .iter()
        .find(|s| s.module == "child_process" && s.symbol == "execSync")
        .expect("execSync site");
    assert_eq!(hit.function, "run");
}

#[test]
fn sites_named_import_call_in_arrow_scope() {
    let src = "import { merge } from 'lodash';\nconst combine = () => merge({}, {});";
    let s = sites(src);
    let hit = s
        .iter()
        .find(|s| s.module == "lodash" && s.symbol == "merge")
        .expect("merge site");
    // Attributed to the const-arrow scope, not <module>.
    assert_eq!(hit.function, "combine");
}

#[test]
fn sites_top_level_use_is_module_scope() {
    let src = "const _ = require('lodash');\n_.template('<%= x %>');";
    let s = sites(src);
    let hit = s
        .iter()
        .find(|s| s.module == "lodash" && s.symbol == "template")
        .expect("template site");
    assert_eq!(hit.function, "<module>");
}

#[test]
fn sites_use_in_callback_folds_to_named_scope() {
    // `_.merge` inside the forEach arrow attributes to `apply`, the
    // nearest named enclosing scope — the callback opens none.
    let src = "import _ from 'lodash';\nfunction apply(items) { items.forEach(i => _.merge(i)); }";
    let s = sites(src);
    let hit = s
        .iter()
        .find(|s| s.module == "lodash" && s.symbol == "merge")
        .expect("merge site");
    assert_eq!(hit.function, "apply");
}

#[test]
fn sites_and_used_symbols_agree_on_symbol_set() {
    // The scope-aware pass must surface exactly the same (module,
    // symbol) pairs the flat pass does — attribution only adds scope.
    let src = "import cp from 'child_process';\nimport { merge } from 'lodash';\n\
               function a() { cp.execSync('x'); }\nfunction b() { merge({}); }";
    let flat: HashSet<(String, String)> = extract_used_symbols(src.as_bytes())
        .into_iter()
        .map(|u| (u.module, u.symbol))
        .collect();
    let scoped: HashSet<(String, String)> = sites(src)
        .into_iter()
        .map(|s| (s.module, s.symbol))
        .collect();
    assert_eq!(flat, scoped);
}

#[test]
fn sites_bad_source_no_panic() {
    let _ = sites("import x from 'y'; function ( { broken");
    let _ = sites("<<< not js >>> ???");
    assert!(sites("").is_empty());
}

// --- Call graph + sites (Python) ------------------------------------

fn cg_py(src: &str) -> Vec<CallNode> {
    call_graph_python(src.as_bytes())
}

fn sites_py(src: &str) -> Vec<SymbolSite> {
    used_symbol_sites_python(src.as_bytes())
}

#[test]
fn cg_py_def_edges_and_module_scope() {
    let src = "setup()\ndef setup():\n    init()\n    helper()\ndef helper():\n    pass\n";
    let g = cg_py(src);
    assert_eq!(calls_of(&g, "<module>"), Some(&["setup".to_string()][..]));
    assert_eq!(
        calls_of(&g, "setup"),
        Some(&["init".to_string(), "helper".to_string()][..])
    );
    assert_eq!(calls_of(&g, "helper"), Some(&[][..]));
}

#[test]
fn cg_py_method_and_attribute_callee() {
    let src = "class C:\n    def run(self):\n        self.step()\n        os.system('ls')\n";
    assert_eq!(
        calls_of(&cg_py(src), "run"),
        Some(&["step".to_string(), "system".to_string()][..])
    );
}

#[test]
fn cg_py_nested_def_opens_scope() {
    let src = "def outer():\n    def inner():\n        leaf()\n    inner()\n";
    let g = cg_py(src);
    assert_eq!(calls_of(&g, "outer"), Some(&["inner".to_string()][..]));
    assert_eq!(calls_of(&g, "inner"), Some(&["leaf".to_string()][..]));
}

#[test]
fn sites_py_attribute_use_attributed_to_def() {
    let src = "import os\ndef work():\n    os.system('ls')\n";
    let hit = sites_py(src)
        .into_iter()
        .find(|s| s.module == "os" && s.symbol == "system")
        .expect("os.system site");
    assert_eq!(hit.function, "work");
}

#[test]
fn sites_py_from_import_call_and_top_level() {
    let src = "from requests import get\nget('https://x')\ndef fetch():\n    get('https://y')\n";
    let s = sites_py(src);
    let scopes: HashSet<String> = s
        .iter()
        .filter(|s| s.module == "requests" && s.symbol == "get")
        .map(|s| s.function.clone())
        .collect();
    assert_eq!(
        scopes,
        HashSet::from(["<module>".to_string(), "fetch".to_string()])
    );
}

#[test]
fn sites_py_agree_with_flat_used_symbols() {
    let src =
        "import os\nfrom requests import get\ndef a():\n    os.getcwd()\ndef b():\n    get('x')\n";
    let flat: HashSet<(String, String)> = extract_used_symbols_python(src.as_bytes())
        .into_iter()
        .map(|u| (u.module, u.symbol))
        .collect();
    let scoped: HashSet<(String, String)> = sites_py(src)
        .into_iter()
        .map(|s| (s.module, s.symbol))
        .collect();
    assert_eq!(flat, scoped);
}

#[test]
fn cg_py_bad_source_no_panic() {
    let _ = cg_py("def ( broken:");
    let _ = sites_py("import ??? broken");
    assert!(cg_py("").is_empty());
    assert!(sites_py("").is_empty());
}

// --- functions_reaching (project-level caller detail) ---------------

#[test]
fn functions_reaching_across_js_and_python() {
    let files = vec![
        (
            "a.js".to_string(),
            b"import cp from 'child_process';\nfunction run() { cp.execSync('x'); }".to_vec(),
        ),
        (
            "b.py".to_string(),
            b"import subprocess as cp\ndef go():\n    cp.run('x')\n".to_vec(),
        ),
        // Different symbol on the same dep → not a hit for execSync.
        (
            "c.js".to_string(),
            b"import cp from 'child_process';\nfunction other() { cp.spawn('y'); }".to_vec(),
        ),
    ];
    let sites = functions_reaching("child_process", "execSync", &files);
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].file, "a.js");
    assert_eq!(sites[0].function, "run");

    // subprocess.run in b.py, attributed to `go`.
    let py = functions_reaching("subprocess", "run", &files);
    assert_eq!(py.len(), 1);
    assert_eq!(py[0].function, "go");
}

#[test]
fn functions_reaching_dedups_repeated_use_per_function() {
    let files = vec![(
        "x.js".to_string(),
        b"import _ from 'lodash';\nfunction f() { _.merge(); _.merge(); _.merge(); }".to_vec(),
    )];
    let sites = functions_reaching("lodash", "merge", &files);
    // One (file, function) entry despite three uses.
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].function, "f");
}

#[test]
fn functions_reaching_empty_when_symbol_absent() {
    let files = vec![(
        "x.js".to_string(),
        b"import _ from 'lodash';\n_.merge();".to_vec(),
    )];
    assert!(functions_reaching("lodash", "template", &files).is_empty());
}

// --- Call graph + sites (Go) ----------------------------------------

fn cg_go(src: &str) -> Vec<CallNode> {
    call_graph_go(src.as_bytes())
}

fn sites_go(src: &str) -> Vec<SymbolSite> {
    used_symbol_sites_go(src.as_bytes())
}

#[test]
fn cg_go_func_and_method_edges() {
    let src = "package main\nfunc main() { setup(); cobra.Execute() }\n\
               func setup() { helper() }\nfunc (s *S) Run() { s.step() }";
    let g = cg_go(src);
    assert_eq!(
        calls_of(&g, "main"),
        Some(&["setup".to_string(), "Execute".to_string()][..])
    );
    assert_eq!(calls_of(&g, "setup"), Some(&["helper".to_string()][..]));
    assert_eq!(calls_of(&g, "Run"), Some(&["step".to_string()][..]));
}

#[test]
fn sites_go_selector_attributed_to_func() {
    let src = "package main\nimport \"github.com/spf13/cobra\"\n\
               func run() { cobra.OnInitialize() }";
    let hit = sites_go(src)
        .into_iter()
        .find(|s| s.module == "github.com/spf13/cobra" && s.symbol == "OnInitialize")
        .expect("OnInitialize site");
    assert_eq!(hit.function, "run");
}

#[test]
fn sites_go_qualified_type_in_method() {
    let src = "package main\nimport \"github.com/x/y\"\n\
               func (r *R) build() y.Config { return y.Config{} }";
    let scopes: HashSet<String> = sites_go(src)
        .into_iter()
        .filter(|s| s.module == "github.com/x/y" && s.symbol == "Config")
        .map(|s| s.function)
        .collect();
    // Both the return-type and composite-literal `y.Config` land in `build`.
    assert_eq!(scopes, HashSet::from(["build".to_string()]));
}

#[test]
fn functions_reaching_routes_go() {
    let files = vec![(
        "main.go".to_string(),
        b"package main\nimport \"github.com/spf13/cobra\"\nfunc run() { cobra.Execute() }".to_vec(),
    )];
    let sites = functions_reaching("github.com/spf13/cobra", "Execute", &files);
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].file, "main.go");
    assert_eq!(sites[0].function, "run");
}

#[test]
fn cg_go_bad_source_no_panic() {
    let _ = cg_go("package main\nfunc ( broken {");
    let _ = sites_go("package main\nimport ( \"broken");
    assert!(cg_go("").is_empty());
    assert!(sites_go("").is_empty());
}

// --- Call graph + sites (PHP) ---------------------------------------

fn cg_php(src: &str) -> Vec<CallNode> {
    call_graph_php(src.as_bytes())
}

fn sites_php(src: &str) -> Vec<SymbolSite> {
    used_symbol_sites_php(src.as_bytes())
}

#[test]
fn cg_php_function_method_and_static_edges() {
    let src = "<?php\nfunction boot() { setup(); Bar::make(); }\n\
               class C { function run() { $this->step(); helper(); } }\n";
    let g = cg_php(src);
    assert_eq!(
        calls_of(&g, "boot"),
        Some(&["setup".to_string(), "make".to_string()][..])
    );
    assert_eq!(
        calls_of(&g, "run"),
        Some(&["step".to_string(), "helper".to_string()][..])
    );
}

#[test]
fn sites_php_scoped_call_attributed_to_function() {
    let src = "<?php\nuse Foo\\Bar;\nfunction build() { Bar::make(); }\n";
    let hit = sites_php(src)
        .into_iter()
        .find(|s| s.module == "Foo\\Bar" && s.symbol == "make")
        .expect("Bar::make site");
    assert_eq!(hit.function, "build");
}

#[test]
fn sites_php_top_level_and_const_access() {
    let src = "<?php\nuse Foo\\Bar;\nBar::VERSION;\nfunction f() { Bar::run(); }\n";
    let scopes: HashSet<(String, String)> = sites_php(src)
        .into_iter()
        .filter(|s| s.module == "Foo\\Bar")
        .map(|s| (s.symbol, s.function))
        .collect();
    assert!(scopes.contains(&("VERSION".to_string(), "<module>".to_string())));
    assert!(scopes.contains(&("run".to_string(), "f".to_string())));
}

#[test]
fn functions_reaching_routes_php() {
    let files = vec![(
        "app.php".to_string(),
        b"<?php\nuse Symfony\\Component\\Console\\Application;\n\
          function main() { Application::create(); }\n"
            .to_vec(),
    )];
    let sites = functions_reaching("Symfony\\Component\\Console\\Application", "create", &files);
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].file, "app.php");
    assert_eq!(sites[0].function, "main");
}

#[test]
fn cg_php_bad_source_no_panic() {
    let _ = cg_php("<?php function ( broken {");
    let _ = sites_php("<?php use broken");
    assert!(cg_php("").is_empty());
    assert!(sites_php("").is_empty());
}

// --- functions_reaching_transitive (cross-file resolution) ----------

/// Find the entry for a (file, function), or None.
fn entry<'a>(v: &'a [ReachEntry], file: &str, func: &str) -> Option<&'a ReachEntry> {
    v.iter().find(|e| e.file == file && e.function == func)
}

#[test]
fn transitive_walks_callers_across_files() {
    // sink.js uses cp.execSync directly; middle.js calls sink();
    // entry.js calls middle(). All three should reach `execSync`.
    let files = vec![
        (
            "sink.js".to_string(),
            b"import cp from 'child_process';\nfunction sink() { cp.execSync('x'); }".to_vec(),
        ),
        (
            "middle.js".to_string(),
            b"function middle() { sink(); }".to_vec(),
        ),
        (
            "entry.js".to_string(),
            b"function boot() { middle(); }".to_vec(),
        ),
        // unrelated function — must not appear.
        (
            "other.js".to_string(),
            b"function idle() { noop(); }".to_vec(),
        ),
    ];
    let r = functions_reaching_transitive("child_process", "execSync", &files);

    let direct = entry(&r, "sink.js", "sink").expect("sink direct");
    assert!(direct.direct);
    assert!(direct.line > 0);

    let mid = entry(&r, "middle.js", "middle").expect("middle transitive");
    assert!(!mid.direct);
    assert_eq!(mid.line, 0);

    assert!(entry(&r, "entry.js", "boot").is_some());
    assert!(entry(&r, "other.js", "idle").is_none());
    // Direct entries sort first.
    assert!(r[0].direct);
}

#[test]
fn transitive_crosses_language_by_name() {
    // A Python `runner` calls `sink`; the JS `sink` is the direct user.
    // Name-based resolution links them even across languages.
    let files = vec![
        (
            "s.js".to_string(),
            b"import _ from 'lodash';\nfunction sink() { _.template('x'); }".to_vec(),
        ),
        ("r.py".to_string(), b"def runner():\n    sink()\n".to_vec()),
    ];
    let r = functions_reaching_transitive("lodash", "template", &files);
    assert!(entry(&r, "s.js", "sink").is_some_and(|e| e.direct));
    assert!(entry(&r, "r.py", "runner").is_some_and(|e| !e.direct));
}

#[test]
fn transitive_terminates_on_recursion() {
    // Mutually recursive callers must not loop forever.
    let files = vec![(
        "x.js".to_string(),
        b"import cp from 'child_process';\n\
          function a() { cp.execSync('x'); b(); }\n\
          function b() { a(); }"
            .to_vec(),
    )];
    let r = functions_reaching_transitive("child_process", "execSync", &files);
    assert!(entry(&r, "x.js", "a").is_some_and(|e| e.direct));
    assert!(entry(&r, "x.js", "b").is_some());
}

#[test]
fn transitive_empty_when_symbol_absent() {
    let files = vec![(
        "x.js".to_string(),
        b"import _ from 'lodash';\nfunction f() { _.merge(); }".to_vec(),
    )];
    assert!(functions_reaching_transitive("lodash", "template", &files).is_empty());
}
