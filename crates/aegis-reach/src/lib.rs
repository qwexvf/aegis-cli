//! Source reachability (JS imports). First slice — port of the JavaScript extractor in the depusage library.
//!
//! Given source bytes, this extracts the module imports a JavaScript /
//! TypeScript file declares (ES `import`, dynamic `import("x")`, CommonJS
//! `require("x")`, relative paths). No IO, no network. It answers one
//! question: **is this dependency imported anywhere in the project
//! source?** — which feeds the reachability suppression in
//! [`aegis_domain`] (see [`aegis_domain::downgrade_unused`]).
//!
//! # Scope of this slice
//!
//! Faithful to depusage's JS import pass only:
//!
//! - JavaScript / TypeScript source (one grammar, `tree-sitter-javascript`).
//! - Imports only. Used-symbols resolution and the per-file callgraph
//!   from depusage are **follow-ups**, not ported here.
//! - Per-import `Symbols`/`Aliases`/`Column` are dropped for this slice;
//!   the reachability question only needs the normalized dep key.
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

/// Parse JS/TS source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports(source: &[u8]) -> Vec<Import> {
    let mut parser = Parser::new();
    let language = tree_sitter_javascript::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut imports = Vec::new();
    walk(tree.root_node(), source, &mut imports);
    imports
}

/// The union of non-empty dep keys across all JS/TS files. Files whose
/// extension is not `.js/.ts/.mjs/.cjs/.jsx/.tsx` are skipped.
pub fn imported_dep_keys(files: &[(String, Vec<u8>)]) -> HashSet<String> {
    let mut keys = HashSet::new();
    for (path, bytes) in files {
        if !is_js_ts(path) {
            continue;
        }
        for imp in extract_imports(bytes) {
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

fn is_js_ts(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"]
        .iter()
        .any(|ext| lower.ends_with(ext))
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
}
