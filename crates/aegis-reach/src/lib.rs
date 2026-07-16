//! Source reachability (imports). Port of the depusage import extractors.
//!
//! Given source bytes, this extracts the module imports a source file
//! declares. No IO, no network. It answers one question: **is this
//! dependency imported anywhere in the project source?** — which feeds
//! the reachability suppression in [`aegis_domain`] (see
//! [`aegis_domain::downgrade_unused`]).
//!
//! # Languages
//!
//! - **JavaScript / TypeScript** (`tree-sitter-javascript`): ES `import`,
//!   dynamic `import("x")`, CommonJS `require("x")`, relative paths.
//!   npm dep-key normalization (`@scope/pkg/sub` → `@scope/pkg`).
//! - **Python** (`tree-sitter-python`): `import x`, `import x.y as z`,
//!   `import a, b`, `from a.b import c`, relative `from . import x` /
//!   `from ..pkg import y`, dynamic `__import__("m")` and
//!   `importlib.import_module("m")`. PyPI dep-key normalization to the
//!   top-level package name (`foo.bar` → `foo`, relative → empty);
//!   stdlib is not specially filtered.
//!
//! [`imported_dep_keys`] / [`reachability_of`] dispatch on file
//! extension: `.js/.ts/.mjs/.cjs/.jsx/.tsx` → JS, `.py/.pyi` → Python.
//!
//! # Scope of this slice
//!
//! Imports only. Used-symbols resolution and the per-file callgraph
//! from depusage are **follow-ups**, not ported here — nor are further
//! languages. Per-import `Symbols`/`Aliases`/`Column` are dropped; the
//! reachability question only needs the normalized dep key.
//!
//! # Degradation
//!
//! Bad source never panics: a parse that fails yields an empty result.

use std::collections::HashSet;

use aegis_domain::Reachability;
use tree_sitter::{Node, Parser};

/// Classifies how a module reference enters a file. Mirrors depusage's
/// `ImportKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// Top-level static ES import: `import x from 'm'`, `import 'm'`.
    Static,
    /// Runtime `import('m')` expression with a literal argument.
    Dynamic,
    /// CommonJS `require('m')`.
    Require,
    /// Same-project path (`./x`, `../x`, `/abs`). `dep_key` is empty.
    Relative,
}

/// A single reference to an external (or relative) module.
///
/// `module` is the verbatim string from the source. `dep_key` is the npm
/// normalization to a lockfile key (`@scope/pkg/sub` → `@scope/pkg`,
/// `lodash/fp` → `lodash`); empty when it can't resolve to a registry key
/// (relative, absolute, or `node:` scheme).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub dep_key: String,
    pub kind: ImportKind,
    pub line: usize,
}

/// Which grammar to run the import pass with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// JavaScript / TypeScript (`tree-sitter-javascript`).
    JavaScript,
    /// Python (`tree-sitter-python`).
    Python,
}

/// Parse JS/TS source and return every import it declares.
///
/// JS-defaulting wrapper over [`extract_with`] — kept for the original
/// single-language API. A parse failure yields an empty vec — never
/// panics.
pub fn extract_imports(source: &[u8]) -> Vec<Import> {
    extract_with(Language::JavaScript, source)
}

/// Parse Python source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_python(source: &[u8]) -> Vec<Import> {
    extract_with(Language::Python, source)
}

/// Parse `source` with the grammar for `lang` and return every import.
///
/// A parse failure (or a grammar that won't load) yields an empty vec —
/// never panics.
pub fn extract_with(lang: Language, source: &[u8]) -> Vec<Import> {
    let mut parser = Parser::new();
    let language = match lang {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
    };
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut imports = Vec::new();
    match lang {
        Language::JavaScript => walk(tree.root_node(), source, &mut imports),
        Language::Python => walk_python(tree.root_node(), source, &mut imports),
    }
    imports
}

/// The union of non-empty dep keys across all recognized source files.
/// Files are routed by extension — `.js/.ts/.mjs/.cjs/.jsx/.tsx` through
/// the JS extractor, `.py/.pyi` through the Python extractor. Any other
/// extension is skipped.
pub fn imported_dep_keys(files: &[(String, Vec<u8>)]) -> HashSet<String> {
    let mut keys = HashSet::new();
    for (path, bytes) in files {
        let Some(lang) = language_for(path) else {
            continue;
        };
        for imp in extract_with(lang, bytes) {
            if !imp.dep_key.is_empty() {
                keys.insert(imp.dep_key);
            }
        }
    }
    keys
}

/// [`Reachability::Used`] if `dep_key` is imported by any project source
/// file, otherwise [`Reachability::Unused`]. This is the value that feeds
/// [`aegis_domain::downgrade_unused`].
pub fn reachability_of(dep_key: &str, files: &[(String, Vec<u8>)]) -> Reachability {
    if imported_dep_keys(files).contains(dep_key) {
        Reachability::Used
    } else {
        Reachability::Unused
    }
}

/// Normalize a raw npm module string to a lockfile-key form.
///
/// ```text
/// "lodash"          -> "lodash"
/// "lodash/merge"    -> "lodash"
/// "@scope/pkg"      -> "@scope/pkg"
/// "@scope/pkg/sub"  -> "@scope/pkg"
/// "./foo"           -> ""   (relative)
/// "/abs/path"       -> ""   (absolute)
/// "node:fs"         -> ""   (node builtin scheme)
/// ""                -> ""
/// ```
///
/// Bare builtin names (`fs`, `path`, ...) are **not** stripped — that's
/// the consumer's job. Mirrors depusage's `DepKey`.
pub fn dep_key(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if is_relative(raw) || raw.starts_with("node:") {
        return String::new();
    }
    if let Some(rest) = raw.strip_prefix('@') {
        // Scoped: keep first two segments.
        match rest.split_once('/') {
            // "@scope/pkg[/sub...]" — keep "@scope/pkg".
            Some((scope, tail)) => {
                let pkg = tail.split('/').next().unwrap_or("");
                format!("@{scope}/{pkg}")
            }
            // "@something" with no slash — malformed but return as-is.
            None => raw.to_string(),
        }
    } else if let Some(i) = raw.find('/') {
        // Unscoped: keep first segment (i > 0 always here).
        raw[..i].to_string()
    } else {
        raw.to_string()
    }
}

/// Whether the raw module string is a relative or absolute path. Mirrors
/// depusage's `IsRelative`.
fn is_relative(raw: &str) -> bool {
    raw.starts_with("./")
        || raw.starts_with("../")
        || raw == "."
        || raw == ".."
        || raw.starts_with('/')
}

/// Pick the extractor language for a file path by extension, or `None`
/// if the extension isn't recognized.
fn language_for(path: &str) -> Option<Language> {
    let lower = path.to_ascii_lowercase();
    if [".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        Some(Language::JavaScript)
    } else if [".py", ".pyi"].iter().any(|ext| lower.ends_with(ext)) {
        Some(Language::Python)
    } else {
        None
    }
}

/// Recursively walk the tree, converting import containers into records.
fn walk(node: Node, body: &[u8], out: &mut Vec<Import>) {
    match node.kind() {
        "import_statement" => {
            if let Some(imp) = parse_import_statement(node, body) {
                out.push(imp);
            }
        }
        "call_expression" => {
            if let Some(imp) = parse_call_expression(node, body) {
                out.push(imp);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, body, out);
    }
}

/// Turn an `import_statement` node into one [`Import`].
fn parse_import_statement(node: Node, body: &[u8]) -> Option<Import> {
    let source = node.child_by_field_name("source")?;
    let module = string_literal_value(source, body)?;
    Some(build_import(module, ImportKind::Static, node))
}

/// Handle dynamic `import('m')` and CommonJS `require('m')` call
/// expressions. Anything else returns `None`.
fn parse_call_expression(node: Node, body: &[u8]) -> Option<Import> {
    let function = node.child_by_field_name("function")?;
    let kind = match function.kind() {
        // `import('m')` — tree-sitter exposes the keyword as an `import` node.
        "import" => ImportKind::Dynamic,
        // `require('m')` — bare identifier form only.
        "identifier" if function.utf8_text(body).ok()? == "require" => ImportKind::Require,
        _ => return None,
    };
    let args = node.child_by_field_name("arguments")?;
    let module = first_string_arg(args, body)?;
    Some(build_import(module, kind, node))
}

/// Assemble an [`Import`], flipping the kind to `Relative` for a
/// relative/absolute module path.
fn build_import(module: String, kind: ImportKind, node: Node) -> Import {
    let kind = if is_relative(&module) {
        ImportKind::Relative
    } else {
        kind
    };
    Import {
        dep_key: dep_key(&module),
        module,
        kind,
        line: node.start_position().row + 1,
    }
}

/// The first argument of a call's `arguments` node, if it is a string
/// literal. A computed (non-string) first argument returns `None`.
fn first_string_arg(args: Node, body: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    let first = args.named_children(&mut cursor).next();
    match first {
        Some(child) if matches!(child.kind(), "string" | "template_string") => {
            string_literal_value(child, body)
        }
        // No args, or a first arg that isn't a string literal — computed.
        _ => None,
    }
}

/// Inner content of a `string` / `template_string` node. A template with
/// a `${}` substitution is computed and returns `None`; an empty string
/// literal returns `Some("")`.
fn string_literal_value(node: Node, body: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_fragment" => return child.utf8_text(body).ok().map(str::to_string),
            "template_substitution" => return None,
            _ => {}
        }
    }
    // Empty literal ('' or ""): no named children.
    if node.named_child_count() == 0 {
        return Some(String::new());
    }
    None
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

/// Normalize a raw Python module path to its top-level package name (the
/// PyPI dep key in most cases).
///
/// ```text
/// "requests"          -> "requests"
/// "requests.adapters" -> "requests"
/// "urllib.parse"      -> "urllib"
/// ".local"            -> ""   (relative)
/// "..pkg.x"           -> ""   (relative)
/// ""                  -> ""
/// ```
///
/// Stdlib is not filtered — `os.path` normalizes to `os` like any other
/// dotted name. Namespace packages whose top-level differs from the PyPI
/// distribution (`google.cloud.storage` from `google-cloud-storage`)
/// need consumer-side mapping. Mirrors depusage's Python `DepKey`.
pub fn dep_key_python(raw: &str) -> String {
    if raw.is_empty() || is_relative_python(raw) {
        return String::new();
    }
    match raw.find('.') {
        Some(i) if i > 0 => raw[..i].to_string(),
        _ => raw.to_string(),
    }
}

/// Whether a Python module path uses leading-dot relative notation
/// (`.x`, `..y.z`, `.`). Mirrors depusage's Python `IsRelative`.
fn is_relative_python(raw: &str) -> bool {
    raw.starts_with('.')
}

/// Recursively walk a Python tree, converting import containers into
/// records.
fn walk_python(node: Node, body: &[u8], out: &mut Vec<Import>) {
    match node.kind() {
        "import_statement" => parse_py_import_statement(node, body, out),
        "import_from_statement" => {
            if let Some(imp) = parse_py_import_from(node, body) {
                out.push(imp);
            }
        }
        "call" => {
            if let Some(imp) = parse_py_dynamic_call(node, body) {
                out.push(imp);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_python(child, body, out);
    }
}

/// Handle `import a, b as c, d.e` — each `dotted_name` / `aliased_import`
/// in the comma list becomes its own [`Import`].
fn parse_py_import_statement(node: Node, body: &[u8], out: &mut Vec<Import>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let module = match child.kind() {
            "dotted_name" => child.utf8_text(body).ok().map(str::to_string),
            "aliased_import" => child
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(body).ok())
                .map(str::to_string),
            _ => None,
        };
        if let Some(module) = module {
            out.push(build_import_py(module, node));
        }
    }
}

/// Handle `from foo.bar import a, b` and relative `from . import x` /
/// `from ..pkg import y`. The imported symbol names are dropped for this
/// slice — only the module and its dep key matter.
fn parse_py_import_from(node: Node, body: &[u8]) -> Option<Import> {
    let module_node = node.child_by_field_name("module_name")?;
    // For `from .x import y`, the module text already includes the dots.
    let module = module_node.utf8_text(body).ok()?.to_string();
    if module.is_empty() {
        return None;
    }
    Some(build_import_py(module, node))
}

/// Handle `__import__('m')` and `importlib.import_module('m')`. Returns
/// `None` if this isn't one of those calls or the first argument isn't a
/// string literal.
fn parse_py_dynamic_call(node: Node, body: &[u8]) -> Option<Import> {
    let function = node.child_by_field_name("function")?;
    let is_dynamic = match function.kind() {
        "identifier" => function.utf8_text(body).ok()? == "__import__",
        // `importlib.import_module(...)`
        "attribute" => {
            let object = function.child_by_field_name("object")?;
            let attribute = function.child_by_field_name("attribute")?;
            object.utf8_text(body).ok()? == "importlib"
                && attribute.utf8_text(body).ok()? == "import_module"
        }
        _ => false,
    };
    if !is_dynamic {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let first = args.named_children(&mut cursor).next()?;
    if first.kind() != "string" {
        return None;
    }
    let module = py_string_literal_value(first, body)?;
    let kind = if is_relative_python(&module) {
        ImportKind::Relative
    } else {
        ImportKind::Dynamic
    };
    Some(Import {
        dep_key: dep_key_python(&module),
        module,
        kind,
        line: node.start_position().row + 1,
    })
}

/// Assemble a static Python [`Import`], flipping the kind to `Relative`
/// for a leading-dot module path.
fn build_import_py(module: String, node: Node) -> Import {
    let kind = if is_relative_python(&module) {
        ImportKind::Relative
    } else {
        ImportKind::Static
    };
    Import {
        dep_key: dep_key_python(&module),
        module,
        kind,
        line: node.start_position().row + 1,
    }
}

/// Inner content of a Python `string` node. An f-string with an
/// `interpolation` returns `None`; an empty literal returns `Some("")`.
fn py_string_literal_value(node: Node, body: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_content" => return child.utf8_text(body).ok().map(str::to_string),
            "interpolation" => return None,
            _ => {}
        }
    }
    if node.named_child_count() == 0 {
        return Some(String::new());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str) -> Vec<Import> {
        extract_imports(src.as_bytes())
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
}
