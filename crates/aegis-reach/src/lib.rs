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
//! - **Go** (`tree-sitter-go`): `import "path/to/pkg"`, grouped
//!   `import ( ... )`, aliased / dot (`.`) / blank (`_`) imports. The Go
//!   import path *is* the dep key (no truncation); stdlib paths (no `.`
//!   in the first segment) and `C` normalize to empty. Go has no
//!   relative-import concept.
//! - **PHP** (`tree-sitter-php`): `use A\B\C;` (incl. `as` alias and
//!   group `use A\{B, C};`), and runtime `require`/`include`/
//!   `require_once`/`include_once "file"`. Dep key is always empty —
//!   Composer maps namespaces to packages via composer.json autoload,
//!   which needs project-side data (mirrors depusage's PHP `DepKey`).
//! - **Ruby** (`tree-sitter-ruby`): `require "x"`, `require_relative "x"`
//!   (relative → empty dep key), `gem "x"`, `load`, `autoload`. Dep key
//!   is the first path segment (`foo/bar` → `foo`).
//! - **Rust** (`tree-sitter-rust`): `use a::b::C;` (incl. `use a::{b, c}`
//!   lists and `use x as y` aliases) and `extern crate x;`. Dep key is the
//!   first path segment / crate name; the path roots `crate`/`self`/`super`
//!   and the prelude crates `std`/`core`/`alloc` normalize to empty.
//! - **Java** (`tree-sitter-java`): `import a.b.C;`, `import static a.b.C.m;`,
//!   and wildcard `import a.b.*;`. Dep key is the package prefix (a trailing
//!   Capitalized type segment is dropped); JDK `java.`/`javax.` normalize to
//!   empty.
//!
//! [`imported_dep_keys`] / [`reachability_of`] dispatch on file
//! extension: `.js/.ts/.mjs/.cjs/.jsx/.tsx` → JS, `.py/.pyi` → Python,
//! `.go` → Go, `.php/.phtml` → PHP, `.rb/.gemspec` → Ruby, `.rs` → Rust,
//! `.java` → Java.
//!
//! # Scope of this slice
//!
//! **Rust and Java stay import-level only**, for the same reason Ruby does
//! (below): a `use serde::Serialize` or `import a.b.C` binds a name, but the
//! symbols a dep actually exposes (trait methods brought into scope, static
//! members, re-exports) can't be correlated back to the import without
//! project-wide type/name resolution the single-file AST can't supply. Both
//! answer only "is this crate/package imported at all?"; a sound
//! function-level pass is out of scope here.
//!
//! Imports for all seven languages. Used-symbols resolution is ported
//! for **JavaScript / TypeScript** ([`UsedSymbol`],
//! [`extract_used_symbols`]), **Python**
//! ([`extract_used_symbols_python`]), **Go**
//! ([`extract_used_symbols_go`]), and **PHP**
//! ([`extract_used_symbols_php`]); [`used_symbols_of`] routes all four.
//! Given the imports a file declares, it tracks which imported bindings
//! are actually referenced and which members are accessed on them
//! (`cp.execSync(...)` → symbol `execSync` on the `child_process`
//! import; `os.system(...)` → symbol `system` on `os`). This answers
//! function-level questions like "the project imports lodash, but does it
//! use `lodash.template`?" against an advisory's affected functions.
//!
//! **Ruby has no used-symbol pass by design**: `require "pg"` / `gem "pg"`
//! load a gem but bind no local — the gem's constants (`PG.connect`)
//! enter the global namespace with no syntactic link back to the require,
//! so there is nothing to correlate a member access against without a
//! constant → gem map the AST can't supply. Ruby reachability stays
//! import-level (is the gem required at all?); a sound function-level
//! pass would need project-wide constant resolution, out of scope here.
//!
//! The intra-file **call graph** ([`CallNode`], `call_graph*`) and its
//! join to the used-symbol pass ([`SymbolSite`], `used_symbol_sites*`)
//! are ported for **JavaScript / TypeScript**, **Python**, **Go**, and
//! **PHP** — caller → callee edges within one file, and each
//! imported-symbol use attributed to its enclosing function scope
//! ([`functions_reaching`] joins them into project-level caller detail).
//! This is additive groundwork: it adds precision (which function reaches
//! a symbol) without ever pruning a call path, so it can't turn a
//! reachable advisory into a false negative. Cross-file call resolution
//! stays a **follow-up** (Ruby is excluded from every symbol pass — see
//! above). Per-import `Symbols`/`Aliases`/`Column` are still dropped from
//! [`Import`]; the used-symbol pass re-derives bindings straight from the
//! AST.
//!
//! # Degradation
//!
//! Bad source never panics: a parse that fails yields an empty result.

use std::collections::{HashMap, HashSet};

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
    /// Go (`tree-sitter-go`).
    Go,
    /// PHP (`tree-sitter-php`).
    Php,
    /// Ruby (`tree-sitter-ruby`).
    Ruby,
    /// Rust (`tree-sitter-rust`).
    Rust,
    /// Java (`tree-sitter-java`).
    Java,
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

/// Parse Go source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_go(source: &[u8]) -> Vec<Import> {
    extract_with(Language::Go, source)
}

/// Parse PHP source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_php(source: &[u8]) -> Vec<Import> {
    extract_with(Language::Php, source)
}

/// Parse Ruby source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_ruby(source: &[u8]) -> Vec<Import> {
    extract_with(Language::Ruby, source)
}

/// Parse Rust source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_rust(source: &[u8]) -> Vec<Import> {
    extract_with(Language::Rust, source)
}

/// Parse Java source and return every import it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_java(source: &[u8]) -> Vec<Import> {
    extract_with(Language::Java, source)
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
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
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
        Language::Go => walk_go(tree.root_node(), source, &mut imports),
        Language::Php => walk_php(tree.root_node(), source, &mut imports),
        Language::Ruby => walk_ruby(tree.root_node(), source, &mut imports),
        Language::Rust => walk_rust(tree.root_node(), source, &mut imports),
        Language::Java => walk_java(tree.root_node(), source, &mut imports),
    }
    imports
}

/// The union of non-empty dep keys across all recognized source files.
/// Files are routed by extension — `.js/.ts/.mjs/.cjs/.jsx/.tsx` through
/// the JS extractor, `.py/.pyi` through Python, `.go` through Go,
/// `.php/.phtml` through PHP, `.rb/.gemspec` through Ruby. Any other
/// extension is skipped. (PHP dep keys are always empty, so PHP files
/// contribute nothing here — see the module docs.)
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

/// Pick the extractor [`Language`] for a file path by extension, or `None`
/// if the extension isn't recognized. Public so callers building a
/// per-ecosystem import index (e.g. the `ci` reachability pass) can route
/// files the same way [`imported_dep_keys`] does.
pub fn language_for_path(path: &str) -> Option<Language> {
    language_for(path)
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
    } else if lower.ends_with(".go") {
        Some(Language::Go)
    } else if [".php", ".phtml"].iter().any(|ext| lower.ends_with(ext)) {
        Some(Language::Php)
    } else if [".rb", ".gemspec"].iter().any(|ext| lower.ends_with(ext)) {
        Some(Language::Ruby)
    } else if lower.ends_with(".rs") {
        Some(Language::Rust)
    } else if lower.ends_with(".java") {
        Some(Language::Java)
    } else {
        None
    }
}

/// Pre-order walk in constant stack space.
///
/// The per-language walkers below used to recurse, one frame per level of AST
/// nesting — and nesting depth comes from the package under analysis, so a
/// deeply nested file (generated bundles reach it without trying; a crafted one
/// can go as deep as it likes) overflowed the stack and aborted the process.
/// A tree cursor visits the same nodes in the same order without recursing.
fn preorder(root: Node, f: &mut impl FnMut(Node)) {
    let mut cursor = root.walk();
    'descend: loop {
        f(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        // Leaf: climb until a node has a next sibling, stopping at the root so
        // a subtree walk never escapes upward into the rest of the tree.
        loop {
            if cursor.node() == root {
                return;
            }
            if cursor.goto_next_sibling() {
                continue 'descend;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Walk the tree, converting import containers into records.
fn walk(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| match n.kind() {
        "import_statement" => {
            if let Some(imp) = parse_import_statement(n, body) {
                out.push(imp);
            }
        }
        "call_expression" => {
            if let Some(imp) = parse_call_expression(n, body) {
                out.push(imp);
            }
        }
        _ => {}
    });
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

/// Walk a Python tree, converting import containers into records.
fn walk_python(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| match n.kind() {
        "import_statement" => parse_py_import_statement(n, body, out),
        "import_from_statement" => {
            if let Some(imp) = parse_py_import_from(n, body) {
                out.push(imp);
            }
        }
        "call" => {
            if let Some(imp) = parse_py_dynamic_call(n, body) {
                out.push(imp);
            }
        }
        _ => {}
    });
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

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

/// Normalize a raw Go import path to its dep key.
///
/// The Go import path *is* the key — modules are addressed by their full
/// import path, not a prefix, so there is no truncation. Standard-library
/// packages (no `.` in the first path segment, e.g. `fmt`,
/// `encoding/json`), the cgo placeholder `C`, and the empty string
/// return empty — they're never a registry dep. Mirrors depusage's Go
/// `DepKey`.
///
/// ```text
/// "fmt"                    -> ""   (stdlib)
/// "encoding/json"          -> ""   (stdlib)
/// "github.com/spf13/cobra" -> "github.com/spf13/cobra"
/// "C"                      -> ""
/// ""                       -> ""
/// ```
pub fn dep_key_go(raw: &str) -> String {
    if raw.is_empty() || raw == "C" {
        return String::new();
    }
    // Std-library heuristic: no "." in the first path segment.
    match raw.find('/') {
        Some(i) if i > 0 => {
            if !raw[..i].contains('.') {
                return String::new();
            }
        }
        _ => {
            if !raw.contains('.') {
                return String::new();
            }
        }
    }
    raw.to_string()
}

/// Walk a Go tree, converting `import_spec` nodes into records. Handles
/// bare, aliased, dot (`.`), and blank (`_`) imports — all are static; the
/// alias itself is dropped for this slice.
fn walk_go(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| {
        if n.kind() == "import_spec" {
            if let Some(imp) = parse_go_import_spec(n, body) {
                out.push(imp);
            }
        }
    });
}

/// Turn an `import_spec` node into one [`Import`]. Reads the `path` field
/// (a quoted string literal); the optional `name` alias is ignored.
fn parse_go_import_spec(node: Node, body: &[u8]) -> Option<Import> {
    let path = node.child_by_field_name("path")?;
    let module = go_string_literal_value(path, body)?;
    Some(Import {
        dep_key: dep_key_go(&module),
        module,
        kind: ImportKind::Static,
        line: node.start_position().row + 1,
    })
}

/// Strip surrounding quotes from an interpreted (`"..."`) or raw
/// (`` `...` ``) Go string literal node.
fn go_string_literal_value(node: Node, body: &[u8]) -> Option<String> {
    let raw = node.utf8_text(body).ok()?.trim();
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'`' && last == b'`') {
            return Some(raw[1..raw.len() - 1].to_string());
        }
    }
    Some(raw.to_string())
}

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

/// PHP dep key — always empty. Composer maps namespaces to packages via
/// composer.json autoload sections, which depusage can't resolve without
/// project-side data. Consumers match the verbatim `module` against
/// composer.lock metadata instead. Mirrors depusage's PHP `DepKey`.
pub fn dep_key_php(_raw: &str) -> String {
    String::new()
}

/// Walk a PHP tree, converting `use` declarations and include/require
/// expressions into records.
fn walk_php(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| match n.kind() {
        "namespace_use_declaration" => parse_php_use_decl(n, body, out),
        "include_expression"
        | "include_once_expression"
        | "require_expression"
        | "require_once_expression" => {
            if let Some(imp) = parse_php_include(n, body) {
                out.push(imp);
            }
        }
        _ => {}
    });
}

/// Handle `use Foo\Bar;`, `use Foo\Bar as B;`, and the group form
/// `use Foo\{Bar, Baz};`. Each clause becomes one static [`Import`]; the
/// `as` alias and imported-symbol name are dropped for this slice.
fn parse_php_use_decl(node: Node, body: &[u8], out: &mut Vec<Import>) {
    let line = node.start_position().row + 1;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "namespace_use_clause" => {
                if let Some(module) = php_use_clause_name(child, "", body) {
                    out.push(php_static_import(module, line));
                }
            }
            "namespace_use_group" => {
                // `use Foo\{Bar, Baz};` — the prefix is the first
                // `namespace_name` child; the clauses carry the suffixes.
                let mut prefix = String::new();
                let mut group_cursor = child.walk();
                for gchild in child.named_children(&mut group_cursor) {
                    match gchild.kind() {
                        "namespace_name" => {
                            prefix = gchild.utf8_text(body).unwrap_or("").to_string();
                        }
                        "namespace_use_clause" | "namespace_use_group_clause" => {
                            if let Some(module) = php_use_clause_name(gchild, &prefix, body) {
                                out.push(php_static_import(module, line));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Resolve the full namespace path of one `use` clause, prepending
/// `prefix` (non-empty inside a `Foo\{Bar}` group). Uses the `name`
/// field, falling back to the first qualified-name-like child for grammar
/// versions that don't label it.
fn php_use_clause_name(clause: Node, prefix: &str, body: &[u8]) -> Option<String> {
    let mut name = clause
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(body).ok())
        .map(str::to_string);
    if name.is_none() {
        let mut cursor = clause.walk();
        for child in clause.named_children(&mut cursor) {
            if matches!(child.kind(), "qualified_name" | "namespace_name" | "name") {
                name = child.utf8_text(body).ok().map(str::to_string);
                break;
            }
        }
    }
    let name = name?;
    if name.is_empty() {
        return None;
    }
    if prefix.is_empty() {
        Some(name)
    } else {
        Some(format!("{prefix}\\{name}"))
    }
}

/// Handle `require '...'` / `include '...'` and their `_once` variants.
/// The argument is a literal file path, which never resolves to a
/// Composer key — kind is `Relative` with an empty dep key (mirrors
/// depusage). A non-literal argument yields `None`.
fn parse_php_include(node: Node, body: &[u8]) -> Option<Import> {
    let mut cursor = node.walk();
    // The include expression's first named child is the loaded argument.
    let child = node.named_children(&mut cursor).next()?;
    if !matches!(child.kind(), "string" | "encapsed_string") {
        return None;
    }
    let module = php_string_value(child, body)?;
    Some(Import {
        module,
        dep_key: String::new(),
        kind: ImportKind::Relative,
        line: node.start_position().row + 1,
    })
}

/// Inner content of a PHP `string` / `encapsed_string` node. An
/// interpolated string returns `None`; an empty literal returns
/// `Some("")`.
fn php_string_value(node: Node, body: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_value" | "string_content" => {
                return child.utf8_text(body).ok().map(str::to_string);
            }
            "interpolation" => return None,
            _ => {}
        }
    }
    if node.named_child_count() == 0 {
        return Some(String::new());
    }
    None
}

/// Assemble a static PHP [`Import`] with an (always-empty) dep key.
fn php_static_import(module: String, line: usize) -> Import {
    Import {
        dep_key: dep_key_php(&module),
        module,
        kind: ImportKind::Static,
        line,
    }
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

/// Normalize a Ruby `require`/`gem` target to its gem name — the first
/// path segment (`foo/bar` → `foo`). Relative paths (`./x`, `../x`,
/// `/abs`) and the empty string return empty. Mirrors depusage's Ruby
/// `DepKey`.
///
/// ```text
/// "rails"                     -> "rails"
/// "active_support/core_ext"   -> "active_support"
/// "./helpers"                 -> ""   (relative)
/// ""                          -> ""
/// ```
pub fn dep_key_ruby(raw: &str) -> String {
    if raw.is_empty() || is_relative_ruby(raw) {
        return String::new();
    }
    match raw.find('/') {
        Some(i) if i > 0 => raw[..i].to_string(),
        _ => raw.to_string(),
    }
}

/// Whether a Ruby require target is a project-local file path rather than
/// a gem. Mirrors depusage's Ruby `IsRelative`.
fn is_relative_ruby(raw: &str) -> bool {
    raw.starts_with("./") || raw.starts_with("../") || raw.starts_with('/')
}

/// Walk a Ruby tree, converting `require`/`require_relative`/`load`/`gem`/
/// `autoload` calls with a literal string argument into records.
fn walk_ruby(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| {
        if n.kind() == "call" {
            if let Some(imp) = parse_ruby_require(n, body) {
                out.push(imp);
            }
        }
    });
}

/// Extract the string-literal argument from a require-family call.
/// `require_relative` (or any relative path) is `Relative` with an empty
/// dep key; everything else is `Require`. A computed (non-literal)
/// argument yields `None`. `autoload` takes a symbol first, then the
/// file string — the symbol is skipped.
fn parse_ruby_require(node: Node, body: &[u8]) -> Option<Import> {
    let method = node.child_by_field_name("method")?;
    if method.kind() != "identifier" {
        return None;
    }
    let method_name = method.utf8_text(body).ok()?;
    if !matches!(
        method_name,
        "require" | "require_relative" | "load" | "gem" | "autoload"
    ) {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.kind() != "string" {
            // `autoload :Sym, 'file'` — skip the leading symbol.
            if method_name == "autoload" {
                continue;
            }
            return None;
        }
        let module = ruby_string_value(child, body)?;
        let (kind, dep_key) = if method_name == "require_relative" || is_relative_ruby(&module) {
            (ImportKind::Relative, String::new())
        } else {
            (ImportKind::Require, dep_key_ruby(&module))
        };
        return Some(Import {
            module,
            dep_key,
            kind,
            line: node.start_position().row + 1,
        });
    }
    None
}

/// Inner content of a Ruby `string` node. An interpolated string
/// (`"#{...}"`) returns `None`; an empty literal returns `Some("")`.
fn ruby_string_value(node: Node, body: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "interpolation" => return None,
            "string_content" => return child.utf8_text(body).ok().map(str::to_string),
            _ => {}
        }
    }
    if node.named_child_count() == 0 {
        return Some(String::new());
    }
    None
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

/// Normalize a raw Rust `use` path (or `extern crate` name) to its dep key —
/// the first path segment, i.e. the crate name. The path-relative roots
/// (`crate`, `self`, `super`) and the implicit-prelude crates (`std`, `core`,
/// `alloc`) resolve to empty — they're never an external registry dep.
///
/// ```text
/// "serde::Serialize"     -> "serde"
/// "tokio::sync::mpsc"    -> "tokio"
/// "crate::foo"           -> ""   (crate-local)
/// "self::bar"            -> ""   (module-relative)
/// "std::collections"     -> ""   (stdlib)
/// "{a, b}"               -> ""   (grouped, no leading path)
/// ""                     -> ""
/// ```
///
/// A crate rename in Cargo.toml (`foo = { package = "bar" }`) means the
/// import name can differ from the published name; resolving that needs the
/// manifest, so consumers reconcile the key against Cargo metadata.
pub fn dep_key_rust(raw: &str) -> String {
    let seg = rust_first_segment(raw);
    match seg {
        "" | "crate" | "self" | "super" | "std" | "core" | "alloc" => String::new(),
        s => s.to_string(),
    }
}

/// First `::`-separated segment of a Rust path, skipping a leading `::` and
/// stopping at any path/list punctuation. `"serde::de::Visitor"` -> `"serde"`,
/// `"foo::{a, b}"` -> `"foo"`, `"{a, b}"` -> `""`.
fn rust_first_segment(raw: &str) -> &str {
    let raw = raw.trim().strip_prefix("::").unwrap_or(raw.trim());
    let end = raw
        .find(|c: char| c == ':' || c == '{' || c == '}' || c == ',' || c.is_whitespace())
        .unwrap_or(raw.len());
    &raw[..end]
}

/// Walk a Rust tree, converting `use` declarations and `extern crate`
/// statements into records. Both are static; aliases (`use x as y`) are
/// dropped — only the crate the path roots at matters.
fn walk_rust(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| match n.kind() {
        "use_declaration" => {
            if let Some(imp) = parse_rust_use(n, body) {
                out.push(imp);
            }
        }
        "extern_crate_declaration" => {
            if let Some(imp) = parse_rust_extern_crate(n, body) {
                out.push(imp);
            }
        }
        _ => {}
    });
}

/// Turn a `use_declaration` into one [`Import`]. Reads the `argument` field
/// (the use tree) verbatim as the module; the dep key is its first segment.
fn parse_rust_use(node: Node, body: &[u8]) -> Option<Import> {
    let arg = node.child_by_field_name("argument")?;
    let module = arg.utf8_text(body).ok()?.to_string();
    Some(Import {
        dep_key: dep_key_rust(&module),
        module,
        kind: ImportKind::Static,
        line: node.start_position().row + 1,
    })
}

/// Turn an `extern crate foo;` declaration into one [`Import`]. The `name`
/// field is the crate; the optional `as` alias is ignored.
fn parse_rust_extern_crate(node: Node, body: &[u8]) -> Option<Import> {
    let name = node.child_by_field_name("name")?;
    let module = name.utf8_text(body).ok()?.to_string();
    Some(Import {
        dep_key: dep_key_rust(&module),
        module,
        kind: ImportKind::Static,
        line: node.start_position().row + 1,
    })
}

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

/// Normalize a raw Java import name (the dotted type/name path, without a
/// trailing `.*`) to its dep key — the **package prefix**. A trailing
/// Capitalized segment is treated as the imported type and dropped
/// (`a.b.C` -> `a.b`); an already-package path (wildcard `a.b.*`, passed as
/// `a.b`) is kept. JDK packages (`java.` / `javax.`) resolve to empty —
/// they're never a registry dep.
///
/// ```text
/// "com.google.common.collect.Lists" -> "com.google.common.collect"
/// "org.apache.commons.lang3"        -> "org.apache.commons.lang3" (wildcard)
/// "java.util.List"                  -> ""   (JDK)
/// "javax.annotation.Nullable"       -> ""   (JDK)
/// ""                                -> ""
/// ```
///
/// Java imports name packages, not Maven artifacts; the `group:artifact`
/// coordinate needs project-side pom/gradle data, so consumers reconcile
/// this package prefix against their dependency metadata.
pub fn dep_key_java(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let pkg = match raw.rfind('.') {
        Some(i)
            if raw[i + 1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase()) =>
        {
            &raw[..i]
        }
        _ => raw,
    };
    if pkg == "java" || pkg == "javax" || pkg.starts_with("java.") || pkg.starts_with("javax.") {
        return String::new();
    }
    pkg.to_string()
}

/// Walk a Java tree, converting `import` declarations into records. Covers
/// single-type (`import a.b.C;`), static (`import static a.b.C.m;`), and
/// on-demand wildcard (`import a.b.*;`) forms — all static.
fn walk_java(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| {
        if n.kind() == "import_declaration" {
            if let Some(imp) = parse_java_import(n, body) {
                out.push(imp);
            }
        }
    });
}

/// Turn an `import_declaration` into one [`Import`]. The dotted name is a
/// `scoped_identifier` / `identifier` child; a sibling `asterisk` marks the
/// on-demand wildcard form. The dep key is the package prefix.
fn parse_java_import(node: Node, body: &[u8]) -> Option<Import> {
    let mut name: Option<String> = None;
    let mut wildcard = false;
    let mut is_static = false;
    let mut cursor = node.walk();
    // include unnamed children so the `static` keyword token is visible.
    for child in node.children(&mut cursor) {
        match child.kind() {
            "scoped_identifier" | "identifier" => {
                name = child.utf8_text(body).ok().map(str::to_string);
            }
            "asterisk" => wildcard = true,
            "static" => is_static = true,
            _ => {}
        }
    }
    let name = name?;
    if name.is_empty() {
        return None;
    }
    let module = if wildcard {
        format!("{name}.*")
    } else {
        name.clone()
    };
    // A static import ends in a member (`...Class.method`); strip that member
    // so the dep key resolves the enclosing type, then its package prefix.
    let key_input = if is_static && !wildcard {
        name.rsplit_once('.').map(|(pkg, _)| pkg).unwrap_or(&name)
    } else {
        &name
    };
    Some(Import {
        dep_key: dep_key_java(key_input),
        module,
        kind: ImportKind::Static,
        line: node.start_position().row + 1,
    })
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript used-symbols
// ---------------------------------------------------------------------------

/// A single use of an imported binding: a member access or call that
/// resolves back to a module import. Port of depusage's `UsedSymbol`
/// (the `DepKey`/`Column` fields are folded away).
///
/// `module` is the imported module in dep-key form when it normalizes to
/// a registry key (`lodash/fp` → `lodash`, `child_process` →
/// `child_process`), otherwise the verbatim module string (relative
/// paths, `node:` builtins). `symbol` is the referenced member or binding
/// name — e.g. `execSync`, `readFile`, `template`, or the sentinel
/// `default` for a directly-called default import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedSymbol {
    pub module: String,
    pub symbol: String,
    pub line: usize,
}

/// A resolved local binding: which module an in-scope identifier refers
/// to, and the canonical symbol within it. `symbol` is `"*"` for a
/// namespace import or a `require` local (member-accessed), `"default"`
/// for a default import, otherwise the named-export name.
struct JsBinding {
    module: String,
    symbol: String,
}

/// Parse JS/TS source and return every use of an imported binding.
///
/// Two passes over one parse: first re-derive local bindings from the
/// file's imports (ES `import` clauses + `const x = require('m')`), then
/// walk member-expression / call-expression usages and correlate them
/// against those bindings. A parse failure yields an empty vec — never
/// panics.
///
/// Correlation rules (mirrors depusage's `collectUsedSymbols`):
/// - `obj.prop` where `obj` is a bound identifier → symbol is `prop`
///   (covers default / namespace / `require` bindings, incl. the head of
///   a member chain like `_.a.b`).
/// - `fn(...)` where `fn` is a bound identifier → symbol is the binding's
///   canonical name (the named-import case: `import { merge }; merge()`).
///   Namespace / `require` bindings (`symbol == "*"`) are skipped here —
///   they only surface useful symbols through member access.
pub fn extract_used_symbols(source: &[u8]) -> Vec<UsedSymbol> {
    let mut parser = Parser::new();
    let language = tree_sitter_javascript::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut bindings = HashMap::new();
    collect_js_bindings(tree.root_node(), source, &mut bindings);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    collect_js_uses(tree.root_node(), source, &bindings, &mut out);
    out
}

/// The union of symbol names used on `dep_key` across every supported
/// file in a project. Files are routed by extension —
/// `.js/.ts/.mjs/.cjs/.jsx/.tsx` through the JS used-symbol pass,
/// `.py/.pyi` through the Python one, `.go` through the Go one,
/// `.php/.phtml` through the PHP one; any other extension is skipped.
/// Ruby has no used-symbol pass by design (`require`/`gem` bind no local
/// — see the module docs), so `.rb` files contribute nothing here. A
/// file whose usages don't reference `dep_key` contributes nothing.
pub fn used_symbols_of(dep_key: &str, files: &[(String, Vec<u8>)]) -> HashSet<String> {
    let mut out = HashSet::new();
    for (path, bytes) in files {
        let uses = match language_for(path) {
            Some(Language::JavaScript) => extract_used_symbols(bytes),
            Some(Language::Python) => extract_used_symbols_python(bytes),
            Some(Language::Go) => extract_used_symbols_go(bytes),
            Some(Language::Php) => extract_used_symbols_php(bytes),
            _ => continue,
        };
        for used in uses {
            if used.module == dep_key {
                out.insert(used.symbol);
            }
        }
    }
    out
}

/// One project location that reaches a dep symbol: the file and the
/// enclosing function (or `<module>`) where the use sits, plus its line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub file: String,
    pub function: String,
    pub line: usize,
}

/// The project functions that reach `symbol` of `dep_key` — one
/// [`CallSite`] per (file, function), so a caller shown once even when it
/// uses the symbol repeatedly (the earliest line is kept). Routes
/// `.js/.ts/.mjs/.cjs/.jsx/.tsx` and `.py/.pyi` files through their
/// scope-attributed symbol-site passes, `.go` through the Go one,
/// `.php/.phtml` through the PHP one; other extensions are skipped (Ruby
/// has no symbol pass at all — see the module docs). Results are sorted
/// by (file, function) for deterministic output.
///
/// This is additive caller detail layered on reachability — it never
/// prunes, so it cannot turn a reachable advisory unreachable.
pub fn functions_reaching(
    dep_key: &str,
    symbol: &str,
    files: &[(String, Vec<u8>)],
) -> Vec<CallSite> {
    // (file, function) -> earliest line seen.
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for (path, bytes) in files {
        for site in symbol_sites_for(path, bytes) {
            if site.module == dep_key && site.symbol == symbol {
                let key = (path.clone(), site.function);
                seen.entry(key)
                    .and_modify(|l| *l = (*l).min(site.line))
                    .or_insert(site.line);
            }
        }
    }
    let mut out: Vec<CallSite> = seen
        .into_iter()
        .map(|((file, function), line)| CallSite {
            file,
            function,
            line,
        })
        .collect();
    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.function.cmp(&b.function)));
    out
}

/// Run the scope-attributed symbol-site pass for `path` by extension,
/// returning `[]` for unsupported/Ruby files. Shared by
/// [`functions_reaching`] and [`functions_reaching_transitive`].
fn symbol_sites_for(path: &str, bytes: &[u8]) -> Vec<SymbolSite> {
    match language_for(path) {
        Some(Language::JavaScript) => used_symbol_sites(bytes),
        Some(Language::Python) => used_symbol_sites_python(bytes),
        Some(Language::Go) => used_symbol_sites_go(bytes),
        Some(Language::Php) => used_symbol_sites_php(bytes),
        _ => Vec::new(),
    }
}

/// Run the intra-file call-graph pass for `path` by extension, returning
/// `[]` for unsupported/Ruby files.
fn call_graph_for(path: &str, bytes: &[u8]) -> Vec<CallNode> {
    match language_for(path) {
        Some(Language::JavaScript) => call_graph(bytes),
        Some(Language::Python) => call_graph_python(bytes),
        Some(Language::Go) => call_graph_go(bytes),
        Some(Language::Php) => call_graph_php(bytes),
        _ => Vec::new(),
    }
}

/// A project function that reaches a dep symbol, either by using it
/// directly or by (transitively) calling a function that does.
///
/// `direct` is true when this function references the symbol itself; the
/// `line` is then the use site. `direct` is false for a transitive-only
/// caller — it reaches the symbol solely through the call graph, so no
/// single use-site line applies and `line` is 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachEntry {
    pub file: String,
    pub function: String,
    pub line: usize,
    pub direct: bool,
}

/// The project functions that reach `symbol` of `dep_key`, **transitively
/// through the call graph** — every direct user (as [`functions_reaching`]
/// finds) plus every function that calls, directly or indirectly, one of
/// those users.
///
/// Resolution is **name-based across files**: a callee token `foo` links
/// to every function named `foo` in the project (cross-file call
/// resolution without a full symbol table). This deliberately
/// over-approximates — a name collision may mark an extra caller reachable
/// — but it can only ever *add* callers, never drop a real one, so it
/// preserves the additive, no-false-negative contract of the reachability
/// layer. Results are sorted direct-first, then by (file, function).
pub fn functions_reaching_transitive(
    dep_key: &str,
    symbol: &str,
    files: &[(String, Vec<u8>)],
) -> Vec<ReachEntry> {
    // Direct users first — these seed the transitive walk.
    let mut entries: HashMap<(String, String), ReachEntry> = HashMap::new();
    let mut frontier: Vec<String> = Vec::new();
    let mut reached_names: HashSet<String> = HashSet::new();
    for (path, bytes) in files {
        for site in symbol_sites_for(path, bytes) {
            if site.module == dep_key && site.symbol == symbol {
                if reached_names.insert(site.function.clone()) {
                    frontier.push(site.function.clone());
                }
                entries
                    .entry((path.clone(), site.function.clone()))
                    .and_modify(|e| {
                        e.direct = true;
                        e.line = e.line.min(site.line);
                    })
                    .or_insert(ReachEntry {
                        file: path.clone(),
                        function: site.function,
                        line: site.line,
                        direct: true,
                    });
            }
        }
    }
    if entries.is_empty() {
        return Vec::new();
    }

    // Reverse call edges: callee name -> the (file, function) sites that
    // call it. Name-based, so it spans files.
    let mut callers_of: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (path, bytes) in files {
        for node in call_graph_for(path, bytes) {
            for callee in node.calls {
                callers_of
                    .entry(callee)
                    .or_default()
                    .push((path.clone(), node.function.clone()));
            }
        }
    }

    // Walk callers transitively over function names.
    while let Some(name) = frontier.pop() {
        let Some(callers) = callers_of.get(&name) else {
            continue;
        };
        for (file, caller) in callers.clone() {
            entries
                .entry((file.clone(), caller.clone()))
                .or_insert(ReachEntry {
                    file,
                    function: caller.clone(),
                    line: 0,
                    direct: false,
                });
            if reached_names.insert(caller.clone()) {
                frontier.push(caller);
            }
        }
    }

    let mut out: Vec<ReachEntry> = entries.into_values().collect();
    out.sort_by(|a, b| {
        b.direct
            .cmp(&a.direct)
            .then(a.file.cmp(&b.file))
            .then(a.function.cmp(&b.function))
    });
    out
}

/// Normalize a module string to the form stored on [`UsedSymbol::module`]:
/// its dep key when non-empty, else the verbatim string.
fn used_symbol_module(module: &str) -> String {
    let key = dep_key(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Recursively walk the JS tree, recording local bindings from `import`
/// statements and `const x = require('m')` declarators.
fn collect_js_bindings(node: Node, body: &[u8], out: &mut HashMap<String, JsBinding>) {
    match node.kind() {
        "import_statement" => js_bindings_from_import(node, body, out),
        "variable_declarator" => js_binding_from_require(node, body, out),
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_js_bindings(child, body, out);
    }
}

/// Bind the locals introduced by one `import_statement`: default
/// (`import X`), namespace (`import * as ns`), and named
/// (`import { a, b as c }`) clauses. A side-effect import binds nothing.
fn js_bindings_from_import(node: Node, body: &[u8], out: &mut HashMap<String, JsBinding>) {
    let Some(source) = node.child_by_field_name("source") else {
        return;
    };
    let Some(module) = string_literal_value(source, body) else {
        return;
    };
    let module = used_symbol_module(&module);

    let mut cursor = node.walk();
    for clause in node.named_children(&mut cursor) {
        if clause.kind() != "import_clause" {
            continue;
        }
        let mut clause_cursor = clause.walk();
        for spec in clause.named_children(&mut clause_cursor) {
            match spec.kind() {
                // `import X from 'm'`
                "identifier" => {
                    if let Ok(local) = spec.utf8_text(body) {
                        out.insert(local.to_string(), js_binding(&module, "default"));
                    }
                }
                // `import * as ns from 'm'`
                "namespace_import" => {
                    let mut ns_cursor = spec.walk();
                    for id in spec.named_children(&mut ns_cursor) {
                        if id.kind() == "identifier" {
                            if let Ok(local) = id.utf8_text(body) {
                                out.insert(local.to_string(), js_binding(&module, "*"));
                            }
                            break;
                        }
                    }
                }
                // `import { a, b as c } from 'm'`
                "named_imports" => {
                    let mut named_cursor = spec.walk();
                    for isp in spec.named_children(&mut named_cursor) {
                        if isp.kind() != "import_specifier" {
                            continue;
                        }
                        let Some(name) = isp.child_by_field_name("name") else {
                            continue;
                        };
                        let Ok(canonical) = name.utf8_text(body) else {
                            continue;
                        };
                        // Aliased? The local name is the alias; else the
                        // canonical name is itself the local.
                        let local = isp
                            .child_by_field_name("alias")
                            .and_then(|a| a.utf8_text(body).ok())
                            .unwrap_or(canonical);
                        out.insert(local.to_string(), js_binding(&module, canonical));
                    }
                }
                _ => {}
            }
        }
    }
}

/// Bind the local of a `const x = require('m')` declarator as a
/// namespace-style binding (`symbol == "*"`) — members accessed on `x`
/// surface the real symbol. A computed require argument, or a value that
/// isn't a bare `require(...)` call, binds nothing.
fn js_binding_from_require(node: Node, body: &[u8], out: &mut HashMap<String, JsBinding>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if name.kind() != "identifier" {
        return;
    }
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    if value.kind() != "call_expression" {
        return;
    }
    let Some(function) = value.child_by_field_name("function") else {
        return;
    };
    if function.kind() != "identifier" || function.utf8_text(body).ok() != Some("require") {
        return;
    }
    let Some(args) = value.child_by_field_name("arguments") else {
        return;
    };
    let Some(module) = first_string_arg(args, body) else {
        return;
    };
    if let Ok(local) = name.utf8_text(body) {
        out.insert(
            local.to_string(),
            js_binding(&used_symbol_module(&module), "*"),
        );
    }
}

/// Construct a [`JsBinding`] from a (already dep-key-normalized) module
/// and a canonical symbol.
fn js_binding(module: &str, symbol: &str) -> JsBinding {
    JsBinding {
        module: module.to_string(),
        symbol: symbol.to_string(),
    }
}

/// Recursively walk the JS tree, correlating member/call usages against
/// the resolved bindings and pushing matches into `out`.
fn collect_js_uses(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, JsBinding>,
    out: &mut Vec<UsedSymbol>,
) {
    match node.kind() {
        "member_expression" => {
            if let (Some(object), Some(property)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("property"),
            ) {
                if object.kind() == "identifier" {
                    if let Ok(name) = object.utf8_text(body) {
                        if let Some(binding) = bindings.get(name) {
                            if let Ok(prop) = property.utf8_text(body) {
                                out.push(UsedSymbol {
                                    module: binding.module.clone(),
                                    symbol: prop.to_string(),
                                    line: property.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(function) = node.child_by_field_name("function") {
                if function.kind() == "identifier" {
                    if let Ok(name) = function.utf8_text(body) {
                        if let Some(binding) = bindings.get(name) {
                            // Namespace / require bindings only surface
                            // symbols through member access — skip here.
                            if binding.symbol != "*" {
                                out.push(UsedSymbol {
                                    module: binding.module.clone(),
                                    symbol: binding.symbol.clone(),
                                    line: function.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_js_uses(child, body, bindings, out);
    }
}

// ---------------------------------------------------------------------------
// Python used-symbols
// ---------------------------------------------------------------------------

/// A resolved Python local binding: which module an in-scope identifier
/// refers to, and the canonical symbol within it. `symbol` is `"*"` for a
/// whole-module import (`import os`, `import numpy as np` — the member
/// resolves at the use site via attribute access), otherwise the named
/// `from`-import symbol (its canonical name, pre-alias). Port of
/// depusage's Python `binding`.
struct PyBinding {
    module: String,
    symbol: String,
}

/// One import's binding-relevant shape, mirroring the depusage
/// `extract.Import` fields (`Symbols` / `Aliases`) that the Rust
/// [`Import`] drops. `raw_module` is the verbatim dotted path (needed for
/// the last-segment local of a whole-module import); `module` is its
/// dep-key form (or verbatim when it doesn't normalize). `aliases` is a
/// list of `(local_alias, canonical)` pairs where `canonical` is `"*"`
/// for an aliased whole-module import.
struct PyImportInfo {
    raw_module: String,
    module: String,
    symbols: Vec<String>,
    aliases: Vec<(String, String)>,
}

/// Parse Python source and return every use of an imported binding.
///
/// Two passes over one parse: first re-derive local bindings from the
/// file's `import` / `from ... import` statements, then walk attribute /
/// call usages and correlate them against those bindings. A parse failure
/// yields an empty vec — never panics.
///
/// Correlation rules (mirrors depusage's `collectUsedSymbols`):
/// - `obj.attr` where `obj` is a bound identifier → symbol is `attr`
///   (covers whole-module bindings: `np.array` → `array`, `os.system` →
///   `system`).
/// - `fn(...)` where `fn` is a bound identifier → symbol is the binding's
///   canonical name (the `from x import y` case: `y()` → `y`; aliased
///   `y as z` then `z()` → `y`). Whole-module bindings (`symbol == "*"`)
///   are skipped here — they only surface symbols through attribute
///   access.
pub fn extract_used_symbols_python(source: &[u8]) -> Vec<UsedSymbol> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut infos = Vec::new();
    collect_py_import_infos(tree.root_node(), source, &mut infos);
    let bindings = build_py_bindings(&infos);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    collect_py_uses(tree.root_node(), source, &bindings, &mut out);
    out
}

/// Normalize a Python module string to the form stored on
/// [`UsedSymbol::module`]: its dep key when non-empty, else the verbatim
/// string (relative imports keep their leading-dot form).
fn used_symbol_module_python(module: &str) -> String {
    let key = dep_key_python(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Last dotted segment of a module path (`os.path` → `path`, `os` →
/// `os`). Port of depusage's `lastDotSegment`.
fn last_dot_segment(s: &str) -> &str {
    match s.rfind('.') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Recursively walk a Python tree, collecting one [`PyImportInfo`] per
/// imported module from `import` and `from ... import` statements.
/// Dynamic `__import__` / `importlib.import_module` calls carry no
/// symbols or aliases and so bind nothing — they are skipped here.
fn collect_py_import_infos(node: Node, body: &[u8], out: &mut Vec<PyImportInfo>) {
    match node.kind() {
        "import_statement" => py_import_infos_from_statement(node, body, out),
        "import_from_statement" => {
            if let Some(info) = py_import_info_from_from(node, body) {
                out.push(info);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_py_import_infos(child, body, out);
    }
}

/// Handle `import a, b as c, d.e` — each `dotted_name` / `aliased_import`
/// becomes one [`PyImportInfo`] with a single `"*"` symbol (aliased forms
/// also record the alias against `"*"`).
fn py_import_infos_from_statement(node: Node, body: &[u8], out: &mut Vec<PyImportInfo>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                if let Ok(raw) = child.utf8_text(body) {
                    out.push(py_star_info(raw, None));
                }
            }
            "aliased_import" => {
                let Some(name) = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(body).ok())
                else {
                    continue;
                };
                let alias = child
                    .child_by_field_name("alias")
                    .and_then(|a| a.utf8_text(body).ok());
                out.push(py_star_info(name, alias));
            }
            _ => {}
        }
    }
}

/// Build a whole-module [`PyImportInfo`] (`symbols == ["*"]`) for
/// `raw_module`, recording `alias` (if any) against `"*"`.
fn py_star_info(raw_module: &str, alias: Option<&str>) -> PyImportInfo {
    PyImportInfo {
        module: used_symbol_module_python(raw_module),
        raw_module: raw_module.to_string(),
        symbols: vec!["*".to_string()],
        aliases: alias
            .map(|a| vec![(a.to_string(), "*".to_string())])
            .unwrap_or_default(),
    }
}

/// Handle `from foo.bar import a, b as c, *` — one [`PyImportInfo`] whose
/// `symbols` are the imported names (canonical, pre-alias) and whose
/// `aliases` map each `as`-rename back to its canonical name.
fn py_import_info_from_from(node: Node, body: &[u8]) -> Option<PyImportInfo> {
    let module_node = node.child_by_field_name("module_name")?;
    let raw_module = module_node.utf8_text(body).ok()?.to_string();
    if raw_module.is_empty() {
        return None;
    }
    let module_id = module_node.id();
    let mut info = PyImportInfo {
        module: used_symbol_module_python(&raw_module),
        raw_module,
        symbols: Vec::new(),
        aliases: Vec::new(),
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.id() == module_id {
            continue;
        }
        match child.kind() {
            "dotted_name" | "identifier" => {
                if let Ok(sym) = child.utf8_text(body) {
                    info.symbols.push(sym.to_string());
                }
            }
            "aliased_import" => {
                let Some(canonical) = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(body).ok())
                else {
                    continue;
                };
                info.symbols.push(canonical.to_string());
                if let Some(alias) = child
                    .child_by_field_name("alias")
                    .and_then(|a| a.utf8_text(body).ok())
                {
                    info.aliases
                        .push((alias.to_string(), canonical.to_string()));
                }
            }
            "wildcard_import" => info.symbols.push("*".to_string()),
            _ => {}
        }
    }
    Some(info)
}

/// Resolve local bindings from the collected imports. Port of depusage's
/// `buildBindings`: aliases bind first, then symbols — a `"*"` symbol
/// binds the module's last dotted segment (unless an alias already covers
/// it), and a named symbol that is some alias's canonical target is
/// skipped (the alias binding already carries it).
fn build_py_bindings(imports: &[PyImportInfo]) -> HashMap<String, PyBinding> {
    let mut out = HashMap::new();
    for imp in imports {
        if imp.raw_module.is_empty() {
            continue;
        }
        for (local, canonical) in &imp.aliases {
            out.insert(
                local.clone(),
                PyBinding {
                    module: imp.module.clone(),
                    symbol: canonical.clone(),
                },
            );
        }
        for sym in &imp.symbols {
            if sym == "*" {
                if imp.aliases.iter().any(|(_, canonical)| canonical == "*") {
                    continue;
                }
                let local = last_dot_segment(&imp.raw_module);
                if local.is_empty() {
                    continue;
                }
                out.insert(
                    local.to_string(),
                    PyBinding {
                        module: imp.module.clone(),
                        symbol: "*".to_string(),
                    },
                );
                continue;
            }
            if imp.aliases.iter().any(|(_, canonical)| canonical == sym) {
                continue;
            }
            out.insert(
                sym.clone(),
                PyBinding {
                    module: imp.module.clone(),
                    symbol: sym.clone(),
                },
            );
        }
    }
    out
}

/// Recursively walk the Python tree, correlating attribute / call usages
/// against the resolved bindings and pushing matches into `out`.
fn collect_py_uses(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, PyBinding>,
    out: &mut Vec<UsedSymbol>,
) {
    match node.kind() {
        "attribute" => {
            if let (Some(object), Some(attribute)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("attribute"),
            ) {
                if object.kind() == "identifier" {
                    if let Ok(name) = object.utf8_text(body) {
                        if let Some(binding) = bindings.get(name) {
                            if let Ok(attr) = attribute.utf8_text(body) {
                                out.push(UsedSymbol {
                                    module: binding.module.clone(),
                                    symbol: attr.to_string(),
                                    line: attribute.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        "call" => {
            if let Some(function) = node.child_by_field_name("function") {
                if function.kind() == "identifier" {
                    if let Ok(name) = function.utf8_text(body) {
                        if let Some(binding) = bindings.get(name) {
                            // Whole-module bindings only surface symbols
                            // through attribute access — skip here.
                            if binding.symbol != "*" {
                                out.push(UsedSymbol {
                                    module: binding.module.clone(),
                                    symbol: binding.symbol.clone(),
                                    line: function.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_py_uses(child, body, bindings, out);
    }
}

// ---------------------------------------------------------------------------
// Go used-symbols
// ---------------------------------------------------------------------------

/// Parse Go source and return every use of an imported package.
///
/// Go has no named-import form — a package is imported whole and its
/// exported identifiers are reached through `pkg.Symbol` selector
/// expressions. So binding is always namespace-style: map each import's
/// local package name to its module, then walk `selector_expression`
/// nodes whose operand is a bound package identifier, emitting the
/// selected field as the symbol (`cobra.Command` → `Command`). A parse
/// failure yields an empty vec — never panics.
///
/// The local name is the import alias when present, else the last path
/// segment of the import path (the conventional package-name heuristic —
/// the real `package` clause of a third-party module isn't available
/// here). Dot imports (`. "pkg"`) merge names into file scope with no
/// qualifier, and blank imports (`_ "pkg"`) are side-effect-only; both
/// bind nothing.
pub fn extract_used_symbols_go(source: &[u8]) -> Vec<UsedSymbol> {
    let mut parser = Parser::new();
    let language = tree_sitter_go::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut bindings = HashMap::new();
    collect_go_bindings(tree.root_node(), source, &mut bindings);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    collect_go_uses(tree.root_node(), source, &bindings, &mut out);
    out
}

/// Normalize a Go import path to the form stored on [`UsedSymbol::module`]:
/// its dep key when non-empty, else the verbatim path (stdlib packages,
/// which never form a registry key, keep their bare name).
fn used_symbol_module_go(module: &str) -> String {
    let key = dep_key_go(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Last slash segment of an import path (`github.com/spf13/cobra` →
/// `cobra`, `fmt` → `fmt`). The conventional Go package-name heuristic.
fn last_slash_segment(s: &str) -> &str {
    match s.rfind('/') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Recursively walk the Go tree, recording one local-package → module
/// binding per `import_spec`.
fn collect_go_bindings(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
    if node.kind() == "import_spec" {
        go_binding_from_spec(node, body, out);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_bindings(child, body, out);
    }
}

/// Resolve the local package name for one `import_spec` and bind it to the
/// module. An explicit alias wins; a `.` (dot) or `_` (blank) alias binds
/// nothing; otherwise the last path segment is the local name.
fn go_binding_from_spec(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    let Some(module) = go_string_literal_value(path, body) else {
        return;
    };
    if module.is_empty() {
        return;
    }
    let local = match node.child_by_field_name("name") {
        Some(name) => {
            let Ok(text) = name.utf8_text(body) else {
                return;
            };
            // dot import merges into scope, blank import is side-effect-only.
            if text == "." || text == "_" {
                return;
            }
            text.to_string()
        }
        None => last_slash_segment(&module).to_string(),
    };
    if local.is_empty() {
        return;
    }
    out.insert(local, used_symbol_module_go(&module));
}

/// Recursively walk the Go tree, emitting a [`UsedSymbol`] for every
/// package-qualified reference to a bound package. Two grammar shapes
/// carry these: value/func selectors (`cobra.OnInitialize()`) parse as a
/// `selector_expression` (`operand` . `field`), while type references
/// (`cobra.Command{}`, `var x cobra.Command`) parse as a `qualified_type`
/// (`package` . `name`). Both resolve when the qualifier identifier is
/// bound.
fn collect_go_uses(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, String>,
    out: &mut Vec<UsedSymbol>,
) {
    let qualified = match node.kind() {
        "selector_expression" => Some(("operand", "field")),
        "qualified_type" => Some(("package", "name")),
        _ => None,
    };
    if let Some((qual_field, sym_field)) = qualified {
        if let (Some(qualifier), Some(symbol)) = (
            node.child_by_field_name(qual_field),
            node.child_by_field_name(sym_field),
        ) {
            // qualifier is an `identifier` in a selector, `package_identifier`
            // in a qualified_type — both are single-token package names.
            if let Ok(name) = qualifier.utf8_text(body) {
                if let Some(module) = bindings.get(name) {
                    if let Ok(sym) = symbol.utf8_text(body) {
                        out.push(UsedSymbol {
                            module: module.clone(),
                            symbol: sym.to_string(),
                            line: symbol.start_position().row + 1,
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_uses(child, body, bindings, out);
    }
}

// ---------------------------------------------------------------------------
// PHP used-symbols
// ---------------------------------------------------------------------------

/// Parse PHP source and return every static use of an imported class.
///
/// A `use Foo\Bar;` statement binds the short name `Bar` (or its `as`
/// alias) into scope. Like Go, the binding is namespace-style — the class
/// is reached whole and its members surface through the `::` accessor. So
/// bind each `use` clause's local name to its fully-qualified module,
/// then walk `scoped_call_expression` (`Bar::make()`) and
/// `class_constant_access_expression` (`Bar::CONST`, `Bar::class`) nodes
/// whose scope is a bound name, emitting the accessed member as the
/// symbol. Bare `new Bar()` and type hints reference no member and so
/// contribute nothing (mirrors the Go/JS namespace rule). A parse failure
/// yields an empty vec — never panics.
///
/// Because [`dep_key_php`] is always empty, [`UsedSymbol::module`] is the
/// verbatim FQN — the same form the PHP import path stores, matched
/// against composer.lock metadata downstream.
pub fn extract_used_symbols_php(source: &[u8]) -> Vec<UsedSymbol> {
    let mut parser = Parser::new();
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut bindings = HashMap::new();
    collect_php_bindings(tree.root_node(), source, &mut bindings);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    collect_php_uses(tree.root_node(), source, &bindings, &mut out);
    out
}

/// Normalize a PHP module (FQN) to the form stored on
/// [`UsedSymbol::module`]. `dep_key_php` is always empty, so this is the
/// verbatim FQN.
fn used_symbol_module_php(module: &str) -> String {
    let key = dep_key_php(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Last backslash segment of a PHP FQN (`Foo\Bar\Baz` → `Baz`). The
/// short class name a bare `use` binds into scope.
fn last_backslash_segment(s: &str) -> &str {
    match s.rfind('\\') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Recursively walk the PHP tree, recording one local-name → module
/// binding per `use` clause.
fn collect_php_bindings(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
    if node.kind() == "namespace_use_declaration" {
        php_bindings_from_use(node, body, out);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_php_bindings(child, body, out);
    }
}

/// Resolve local-name → FQN bindings for one `use` declaration, handling
/// the plain (`use Foo\Bar;`), aliased (`use Foo\Bar as B;`), and group
/// (`use Foo\{Bar, Baz as Q};`) forms.
fn php_bindings_from_use(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
    // In `use Foo\{Bar, Baz};` the group prefix (`Foo`) is a
    // `namespace_name` sibling that precedes the `namespace_use_group` at
    // the declaration level — not a child of the group.
    let mut prefix = String::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "namespace_name" => {
                prefix = child.utf8_text(body).unwrap_or("").to_string();
            }
            "namespace_use_clause" => php_bind_clause(child, "", body, out),
            "namespace_use_group" => {
                let mut group_cursor = child.walk();
                for gchild in child.named_children(&mut group_cursor) {
                    if matches!(
                        gchild.kind(),
                        "namespace_use_clause" | "namespace_use_group_clause"
                    ) {
                        php_bind_clause(gchild, &prefix, body, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Bind one `use` clause's local name (alias if present, else the FQN's
/// last backslash segment) to its module.
fn php_bind_clause(clause: Node, prefix: &str, body: &[u8], out: &mut HashMap<String, String>) {
    let Some(fqn) = php_use_clause_name(clause, prefix, body) else {
        return;
    };
    let local = php_use_clause_alias(clause, body)
        .unwrap_or_else(|| last_backslash_segment(&fqn).to_string());
    if local.is_empty() {
        return;
    }
    out.insert(local, used_symbol_module_php(&fqn));
}

/// The `as` alias of a `use` clause, if any. Uses the `alias` field,
/// falling back to the last `name` child for grammar versions that don't
/// label it (the FQN is a `qualified_name`/`namespace_name`, so a bare
/// `name` child is the alias).
fn php_use_clause_alias(clause: Node, body: &[u8]) -> Option<String> {
    if let Some(alias) = clause
        .child_by_field_name("alias")
        .and_then(|a| a.utf8_text(body).ok())
    {
        return Some(alias.to_string());
    }
    let mut cursor = clause.walk();
    clause
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "name")
        .last()
        .and_then(|c| c.utf8_text(body).ok())
        .map(str::to_string)
}

/// Recursively walk the PHP tree, emitting a [`UsedSymbol`] for every
/// `Class::member` access whose class is a bound local name.
fn collect_php_uses(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, String>,
    out: &mut Vec<UsedSymbol>,
) {
    match node.kind() {
        // `Bar::make(...)` — scope + name fields.
        "scoped_call_expression" => {
            if let (Some(scope), Some(name)) = (
                node.child_by_field_name("scope"),
                node.child_by_field_name("name"),
            ) {
                php_push_use(scope, name, body, bindings, out);
            }
        }
        // `Bar::CONST` / `Bar::class` — first named child is the scope,
        // the trailing one is the constant/`class` name.
        "class_constant_access_expression" => {
            let mut cursor = node.walk();
            let kids: Vec<Node> = node.named_children(&mut cursor).collect();
            if let (Some(scope), Some(name)) = (kids.first(), kids.last()) {
                if kids.len() == 2 {
                    php_push_use(*scope, *name, body, bindings, out);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_php_uses(child, body, bindings, out);
    }
}

/// Push a [`UsedSymbol`] when `scope` is a single-token bound class name.
fn php_push_use(
    scope: Node,
    name: Node,
    body: &[u8],
    bindings: &HashMap<String, String>,
    out: &mut Vec<UsedSymbol>,
) {
    if scope.kind() != "name" {
        return;
    }
    let Ok(local) = scope.utf8_text(body) else {
        return;
    };
    let Some(module) = bindings.get(local) else {
        return;
    };
    if let Ok(sym) = name.utf8_text(body) {
        out.push(UsedSymbol {
            module: module.clone(),
            symbol: sym.to_string(),
            line: name.start_position().row + 1,
        });
    }
}

// ---------------------------------------------------------------------------
// Call graph (JavaScript / TypeScript)
// ---------------------------------------------------------------------------

/// One node in a file's intra-file call graph: a named function scope and
/// the callee tokens invoked directly within it.
///
/// `function` is the scope name — a function declaration's name, a class
/// method's name, or the identifier a function/arrow expression is
/// assigned to (`const f = () => …` → `f`). Top-level statements
/// attribute to the sentinel `<module>`. Anonymous inline functions
/// (unnamed callbacks) do **not** open their own scope; their calls fold
/// into the nearest named enclosing scope — a conservative
/// over-approximation (the callback body is treated as reachable whenever
/// its enclosing function is), never a prune. This is groundwork for
/// reachability that will *add* precision without ever hiding a call
/// path, so it can't introduce a false-negative advisory verdict.
///
/// `calls` is the ordered, de-duplicated list of callee tokens: the
/// called identifier for a direct call (`foo()` → `foo`) or the property
/// name for a method call (`obj.bar()` → `bar`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNode {
    pub function: String,
    pub calls: Vec<String>,
}

/// The `<module>` scope name for top-level (non-function-nested) calls.
const MODULE_SCOPE: &str = "<module>";

/// Build the intra-file call graph for JS/TS `source`: one [`CallNode`]
/// per named function scope reached (plus `<module>` when top-level code
/// makes calls), in first-appearance order. A parse failure yields an
/// empty vec — never panics.
///
/// This is the additive groundwork slice of depusage's call graph:
/// caller → callee edges within one file. It does not yet resolve callees
/// to their definitions across files, and deliberately does no dead-code
/// pruning (see [`CallNode`]).
pub fn call_graph(source: &[u8]) -> Vec<CallNode> {
    let mut parser = Parser::new();
    let language = tree_sitter_javascript::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut acc = CgAcc::default();
    cg_walk(tree.root_node(), source, MODULE_SCOPE, &mut acc);
    acc.into_nodes()
}

/// Accumulator that keeps call-graph nodes in first-appearance order while
/// de-duplicating callee tokens per scope.
#[derive(Default)]
struct CgAcc {
    order: Vec<String>,
    index: HashMap<String, usize>,
    calls: Vec<Vec<String>>,
}

impl CgAcc {
    /// Ensure a node exists for `function`, returning its slot index.
    fn ensure(&mut self, function: &str) -> usize {
        if let Some(&i) = self.index.get(function) {
            return i;
        }
        let i = self.order.len();
        self.order.push(function.to_string());
        self.index.insert(function.to_string(), i);
        self.calls.push(Vec::new());
        i
    }

    /// Record that `caller` invokes `callee` (deduped, order-preserving).
    fn add_call(&mut self, caller: &str, callee: &str) {
        let i = self.ensure(caller);
        if !self.calls[i].iter().any(|c| c == callee) {
            self.calls[i].push(callee.to_string());
        }
    }

    fn into_nodes(self) -> Vec<CallNode> {
        self.order
            .into_iter()
            .zip(self.calls)
            .map(|(function, calls)| CallNode { function, calls })
            .collect()
    }
}

/// Recursively walk the JS tree, tracking the enclosing named scope
/// (`current`) and recording one edge per `call_expression`.
fn cg_walk(node: Node, body: &[u8], current: &str, acc: &mut CgAcc) {
    match node.kind() {
        // `function foo() {}` / `function* foo() {}` — opens scope `foo`.
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(body).ok())
            {
                acc.ensure(name);
                recurse_children(node, body, name, acc);
                return;
            }
        }
        // Class method `foo() {}` — opens scope `foo`.
        "method_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(body).ok())
            {
                acc.ensure(name);
                recurse_children(node, body, name, acc);
                return;
            }
        }
        // `const foo = () => {}` / `const foo = function () {}` — the
        // assigned identifier names the function/arrow value's scope.
        "variable_declarator" => {
            if let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                if name.kind() == "identifier"
                    && matches!(value.kind(), "arrow_function" | "function_expression")
                {
                    if let Ok(fname) = name.utf8_text(body) {
                        acc.ensure(fname);
                        cg_walk(value, body, fname, acc);
                        return;
                    }
                }
            }
        }
        // A call reached in `current` scope → one edge.
        "call_expression" => {
            if let Some(callee) = cg_callee_token(node, body) {
                acc.add_call(current, &callee);
            }
            // fall through: nested calls in the arguments still count.
        }
        _ => {}
    }
    recurse_children(node, body, current, acc);
}

/// Walk `node`'s children under scope `current`.
fn recurse_children(node: Node, body: &[u8], current: &str, acc: &mut CgAcc) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cg_walk(child, body, current, acc);
    }
}

/// The callee token of a `call_expression`: the called identifier
/// (`foo()` → `foo`) or, for a method call, the accessed property
/// (`obj.bar()` → `bar`). Other callee shapes (computed access, IIFEs)
/// yield `None`.
fn cg_callee_token(node: Node, body: &[u8]) -> Option<String> {
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "identifier" => function.utf8_text(body).ok().map(str::to_string),
        "member_expression" => function
            .child_by_field_name("property")
            .and_then(|p| p.utf8_text(body).ok())
            .map(str::to_string),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Used-symbol → enclosing-function attribution (JavaScript / TypeScript)
// ---------------------------------------------------------------------------

/// A use of an imported symbol, located to the function scope that
/// contains it. This is [`UsedSymbol`] plus the enclosing scope — the
/// bridge between the used-symbol pass and the [`call_graph`]: it answers
/// "which local function reaches `lodash.template`?", the join point for
/// call-graph-aware reachability.
///
/// `function` follows the same scope rules as [`CallNode`]: a named
/// function/method/const-assigned scope, or `<module>` for top-level use.
/// Uses inside an anonymous callback fold into the nearest named
/// enclosing scope (conservative over-approximation, never a prune).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSite {
    pub module: String,
    pub symbol: String,
    pub function: String,
    pub line: usize,
}

/// Parse JS/TS `source` and return every imported-symbol use, each
/// attributed to its enclosing function scope. Same correlation rules as
/// [`extract_used_symbols`], with scope tracking layered on. A parse
/// failure yields an empty vec — never panics.
pub fn used_symbol_sites(source: &[u8]) -> Vec<SymbolSite> {
    let mut parser = Parser::new();
    let language = tree_sitter_javascript::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut bindings = HashMap::new();
    collect_js_bindings(tree.root_node(), source, &mut bindings);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    site_walk(tree.root_node(), source, &bindings, MODULE_SCOPE, &mut out);
    out
}

/// Recursively walk the JS tree tracking the enclosing named scope
/// (`current`), pushing a [`SymbolSite`] for each member/call use that
/// resolves to a binding. Scope-opening rules mirror [`cg_walk`]; the
/// correlation rules mirror [`collect_js_uses`].
fn site_walk(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, JsBinding>,
    current: &str,
    out: &mut Vec<SymbolSite>,
) {
    match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(body).ok())
            {
                site_recurse(node, body, bindings, name, out);
                return;
            }
        }
        "method_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(body).ok())
            {
                site_recurse(node, body, bindings, name, out);
                return;
            }
        }
        "variable_declarator" => {
            if let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                if name.kind() == "identifier"
                    && matches!(value.kind(), "arrow_function" | "function_expression")
                {
                    if let Ok(fname) = name.utf8_text(body) {
                        site_walk(value, body, bindings, fname, out);
                        return;
                    }
                }
            }
        }
        // `obj.prop` where `obj` is a bound identifier → symbol `prop`.
        "member_expression" => {
            if let (Some(object), Some(property)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("property"),
            ) {
                if object.kind() == "identifier" {
                    if let (Ok(name), Ok(prop)) = (object.utf8_text(body), property.utf8_text(body))
                    {
                        if let Some(binding) = bindings.get(name) {
                            out.push(SymbolSite {
                                module: binding.module.clone(),
                                symbol: prop.to_string(),
                                function: current.to_string(),
                                line: property.start_position().row + 1,
                            });
                        }
                    }
                }
            }
        }
        // `fn(...)` where `fn` is a bound identifier → the binding's
        // canonical name. Namespace/require bindings (`*`) only surface
        // through member access — skip.
        "call_expression" => {
            if let Some(function) = node.child_by_field_name("function") {
                if function.kind() == "identifier" {
                    if let Ok(name) = function.utf8_text(body) {
                        if let Some(binding) = bindings.get(name) {
                            if binding.symbol != "*" {
                                out.push(SymbolSite {
                                    module: binding.module.clone(),
                                    symbol: binding.symbol.clone(),
                                    function: current.to_string(),
                                    line: function.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    site_recurse(node, body, bindings, current, out);
}

/// Walk `node`'s children under scope `current` for the symbol-site pass.
fn site_recurse(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, JsBinding>,
    current: &str,
    out: &mut Vec<SymbolSite>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        site_walk(child, body, bindings, current, out);
    }
}

// ---------------------------------------------------------------------------
// Call graph + symbol-site attribution (Python)
// ---------------------------------------------------------------------------

/// Build the intra-file call graph for Python `source`: one [`CallNode`]
/// per `def` scope reached (plus `<module>` for top-level calls), in
/// first-appearance order. Nested and class-method `def`s open their own
/// scope by name; lambdas are anonymous and fold into the nearest named
/// enclosing scope (never a prune — see [`CallNode`]). A parse failure
/// yields an empty vec — never panics.
pub fn call_graph_python(source: &[u8]) -> Vec<CallNode> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut acc = CgAcc::default();
    cg_walk_py(tree.root_node(), source, MODULE_SCOPE, &mut acc);
    acc.into_nodes()
}

/// Recursively walk the Python tree, tracking the enclosing `def` scope
/// (`current`) and recording one edge per `call`.
fn cg_walk_py(node: Node, body: &[u8], current: &str, acc: &mut CgAcc) {
    if node.kind() == "function_definition" {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(body).ok())
        {
            acc.ensure(name);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                cg_walk_py(child, body, name, acc);
            }
            return;
        }
    }
    if node.kind() == "call" {
        if let Some(callee) = cg_callee_token_py(node, body) {
            acc.add_call(current, &callee);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cg_walk_py(child, body, current, acc);
    }
}

/// The callee token of a Python `call`: the called identifier (`foo()` →
/// `foo`) or, for a method call, the accessed attribute (`obj.bar()` →
/// `bar`). Other callee shapes (subscripts, calls on calls) yield `None`.
fn cg_callee_token_py(node: Node, body: &[u8]) -> Option<String> {
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "identifier" => function.utf8_text(body).ok().map(str::to_string),
        "attribute" => function
            .child_by_field_name("attribute")
            .and_then(|a| a.utf8_text(body).ok())
            .map(str::to_string),
        _ => None,
    }
}

/// Parse Python `source` and return every imported-symbol use, each
/// attributed to its enclosing `def` scope. Same correlation rules as
/// [`extract_used_symbols_python`], with scope tracking layered on. A
/// parse failure yields an empty vec — never panics.
pub fn used_symbol_sites_python(source: &[u8]) -> Vec<SymbolSite> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut infos = Vec::new();
    collect_py_import_infos(tree.root_node(), source, &mut infos);
    let bindings = build_py_bindings(&infos);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    site_walk_py(tree.root_node(), source, &bindings, MODULE_SCOPE, &mut out);
    out
}

/// Recursively walk the Python tree tracking the enclosing `def` scope
/// (`current`), pushing a [`SymbolSite`] for each attribute/call use that
/// resolves to a binding. Scope rules mirror [`cg_walk_py`]; correlation
/// mirrors [`collect_py_uses`].
fn site_walk_py(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, PyBinding>,
    current: &str,
    out: &mut Vec<SymbolSite>,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(body).ok())
            {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    site_walk_py(child, body, bindings, name, out);
                }
                return;
            }
        }
        // `obj.attr` where `obj` is a bound identifier → symbol `attr`.
        "attribute" => {
            if let (Some(object), Some(attribute)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("attribute"),
            ) {
                if object.kind() == "identifier" {
                    if let (Ok(name), Ok(attr)) =
                        (object.utf8_text(body), attribute.utf8_text(body))
                    {
                        if let Some(binding) = bindings.get(name) {
                            out.push(SymbolSite {
                                module: binding.module.clone(),
                                symbol: attr.to_string(),
                                function: current.to_string(),
                                line: attribute.start_position().row + 1,
                            });
                        }
                    }
                }
            }
        }
        // `fn(...)` where `fn` is a bound identifier → the binding's
        // canonical name. Whole-module bindings (`*`) only surface through
        // attribute access — skip.
        "call" => {
            if let Some(function) = node.child_by_field_name("function") {
                if function.kind() == "identifier" {
                    if let Ok(name) = function.utf8_text(body) {
                        if let Some(binding) = bindings.get(name) {
                            if binding.symbol != "*" {
                                out.push(SymbolSite {
                                    module: binding.module.clone(),
                                    symbol: binding.symbol.clone(),
                                    function: current.to_string(),
                                    line: function.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        site_walk_py(child, body, bindings, current, out);
    }
}

// ---------------------------------------------------------------------------
// Call graph + symbol-site attribution (Go)
// ---------------------------------------------------------------------------

/// Build the intra-file call graph for Go `source`: one [`CallNode`] per
/// `func`/method scope reached (plus `<module>` for package-level calls,
/// e.g. in `init`-free top-level composite literals), in first-appearance
/// order. Function literals (`func() { … }`) are anonymous and fold into
/// the nearest named enclosing scope (never a prune). A parse failure
/// yields an empty vec — never panics.
pub fn call_graph_go(source: &[u8]) -> Vec<CallNode> {
    let mut parser = Parser::new();
    let language = tree_sitter_go::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut acc = CgAcc::default();
    cg_walk_go(tree.root_node(), source, MODULE_SCOPE, &mut acc);
    acc.into_nodes()
}

/// Recursively walk the Go tree, tracking the enclosing func/method scope
/// (`current`) and recording one edge per `call_expression`.
fn cg_walk_go(node: Node, body: &[u8], current: &str, acc: &mut CgAcc) {
    if matches!(node.kind(), "function_declaration" | "method_declaration") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(body).ok())
        {
            acc.ensure(name);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                cg_walk_go(child, body, name, acc);
            }
            return;
        }
    }
    if node.kind() == "call_expression" {
        if let Some(callee) = cg_callee_token_go(node, body) {
            acc.add_call(current, &callee);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cg_walk_go(child, body, current, acc);
    }
}

/// The callee token of a Go `call_expression`: the called identifier
/// (`foo()` → `foo`) or, for a package/method call, the selector field
/// (`pkg.Foo()` → `Foo`). Other callee shapes yield `None`.
fn cg_callee_token_go(node: Node, body: &[u8]) -> Option<String> {
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "identifier" => function.utf8_text(body).ok().map(str::to_string),
        "selector_expression" => function
            .child_by_field_name("field")
            .and_then(|f| f.utf8_text(body).ok())
            .map(str::to_string),
        _ => None,
    }
}

/// Parse Go `source` and return every package-qualified symbol use, each
/// attributed to its enclosing func/method scope. Same correlation rules
/// as [`extract_used_symbols_go`] (selector + qualified-type), with scope
/// tracking layered on. A parse failure yields an empty vec — never
/// panics.
pub fn used_symbol_sites_go(source: &[u8]) -> Vec<SymbolSite> {
    let mut parser = Parser::new();
    let language = tree_sitter_go::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut bindings = HashMap::new();
    collect_go_bindings(tree.root_node(), source, &mut bindings);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    site_walk_go(tree.root_node(), source, &bindings, MODULE_SCOPE, &mut out);
    out
}

/// Recursively walk the Go tree tracking the enclosing scope (`current`),
/// pushing a [`SymbolSite`] for each package-qualified reference to a
/// bound package. Scope rules mirror [`cg_walk_go`]; correlation mirrors
/// [`collect_go_uses`].
fn site_walk_go(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, String>,
    current: &str,
    out: &mut Vec<SymbolSite>,
) {
    if matches!(node.kind(), "function_declaration" | "method_declaration") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(body).ok())
        {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                site_walk_go(child, body, bindings, name, out);
            }
            return;
        }
    }
    let qualified = match node.kind() {
        "selector_expression" => Some(("operand", "field")),
        "qualified_type" => Some(("package", "name")),
        _ => None,
    };
    if let Some((qual_field, sym_field)) = qualified {
        if let (Some(qualifier), Some(symbol)) = (
            node.child_by_field_name(qual_field),
            node.child_by_field_name(sym_field),
        ) {
            if let Ok(name) = qualifier.utf8_text(body) {
                if let Some(module) = bindings.get(name) {
                    if let Ok(sym) = symbol.utf8_text(body) {
                        out.push(SymbolSite {
                            module: module.clone(),
                            symbol: sym.to_string(),
                            function: current.to_string(),
                            line: symbol.start_position().row + 1,
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        site_walk_go(child, body, bindings, current, out);
    }
}

// ---------------------------------------------------------------------------
// Call graph + symbol-site attribution (PHP)
// ---------------------------------------------------------------------------

/// Build the intra-file call graph for PHP `source`: one [`CallNode`] per
/// function/method scope reached (plus `<module>` for top-level calls),
/// in first-appearance order. Closures/arrow functions are anonymous and
/// fold into the nearest named enclosing scope (never a prune). A parse
/// failure yields an empty vec — never panics.
pub fn call_graph_php(source: &[u8]) -> Vec<CallNode> {
    let mut parser = Parser::new();
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut acc = CgAcc::default();
    cg_walk_php(tree.root_node(), source, MODULE_SCOPE, &mut acc);
    acc.into_nodes()
}

/// Recursively walk the PHP tree, tracking the enclosing function/method
/// scope (`current`) and recording one edge per call expression.
fn cg_walk_php(node: Node, body: &[u8], current: &str, acc: &mut CgAcc) {
    if matches!(node.kind(), "function_definition" | "method_declaration") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(body).ok())
        {
            acc.ensure(name);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                cg_walk_php(child, body, name, acc);
            }
            return;
        }
    }
    if let Some(callee) = cg_callee_token_php(node, body) {
        acc.add_call(current, &callee);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cg_walk_php(child, body, current, acc);
    }
}

/// The callee token of a PHP call expression: the bare function name for
/// `foo()` / `\Ns\foo()` (last namespace segment), or the method name for
/// `$o->m()`, `$o?->m()`, and `C::m()`. Non-call nodes yield `None`.
fn cg_callee_token_php(node: Node, body: &[u8]) -> Option<String> {
    match node.kind() {
        "function_call_expression" => node
            .child_by_field_name("function")
            .and_then(|f| f.utf8_text(body).ok())
            .map(|s| last_backslash_segment(s).to_string()),
        "member_call_expression" | "nullsafe_member_call_expression" | "scoped_call_expression" => {
            node.child_by_field_name("name")
                .and_then(|n| n.utf8_text(body).ok())
                .map(str::to_string)
        }
        _ => None,
    }
}

/// Parse PHP `source` and return every static `Class::member` use, each
/// attributed to its enclosing function/method scope. Same correlation
/// rules as [`extract_used_symbols_php`], with scope tracking layered on.
/// A parse failure yields an empty vec — never panics.
pub fn used_symbol_sites_php(source: &[u8]) -> Vec<SymbolSite> {
    let mut parser = Parser::new();
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut bindings = HashMap::new();
    collect_php_bindings(tree.root_node(), source, &mut bindings);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    site_walk_php(tree.root_node(), source, &bindings, MODULE_SCOPE, &mut out);
    out
}

/// Recursively walk the PHP tree tracking the enclosing scope (`current`),
/// pushing a [`SymbolSite`] for each `Class::member` access whose class is
/// a bound local name. Scope rules mirror [`cg_walk_php`]; correlation
/// mirrors [`collect_php_uses`].
fn site_walk_php(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, String>,
    current: &str,
    out: &mut Vec<SymbolSite>,
) {
    if matches!(node.kind(), "function_definition" | "method_declaration") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(body).ok())
        {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                site_walk_php(child, body, bindings, name, out);
            }
            return;
        }
    }
    match node.kind() {
        "scoped_call_expression" => {
            if let (Some(scope), Some(name)) = (
                node.child_by_field_name("scope"),
                node.child_by_field_name("name"),
            ) {
                php_push_site(scope, name, body, bindings, current, out);
            }
        }
        "class_constant_access_expression" => {
            let mut cursor = node.walk();
            let kids: Vec<Node> = node.named_children(&mut cursor).collect();
            if kids.len() == 2 {
                php_push_site(kids[0], kids[1], body, bindings, current, out);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        site_walk_php(child, body, bindings, current, out);
    }
}

/// Push a [`SymbolSite`] when `scope` is a single-token bound class name,
/// attributing the member access to the enclosing scope `current`.
fn php_push_site(
    scope: Node,
    name: Node,
    body: &[u8],
    bindings: &HashMap<String, String>,
    current: &str,
    out: &mut Vec<SymbolSite>,
) {
    if scope.kind() != "name" {
        return;
    }
    let Ok(local) = scope.utf8_text(body) else {
        return;
    };
    let Some(module) = bindings.get(local) else {
        return;
    };
    if let Ok(sym) = name.utf8_text(body) {
        out.push(SymbolSite {
            module: module.clone(),
            symbol: sym.to_string(),
            function: current.to_string(),
            line: name.start_position().row + 1,
        });
    }
}

#[cfg(test)]
mod tests {
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
        let imps = extract_rs(
            "use serde::Serialize;\nuse tokio::sync::mpsc;\nuse anyhow::{Result, Context};",
        );
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
        let src = "package x;\nimport com.google.common.collect.Lists;\nimport org.apache.commons.lang3.*;\n";
        let imps = extract_java(src);
        let by_key: std::collections::HashSet<_> =
            imps.iter().map(|i| i.dep_key.as_str()).collect();
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
                b"const cp = require('child_process');\ncp.execSync('ls');\ncp.spawn('x');"
                    .to_vec(),
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
        let src =
            "from requests import get, post\nr = get('https://x')\npost('https://x', json={})";
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
        let syms = used_go(
            "package main\nimport co \"github.com/spf13/cobra\"\nfunc main() { co.Execute() }",
        );
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
        assert!(
            used_go("package main\nimport . \"fmt\"\nfunc main() { Println(\"x\") }").is_empty()
        );
    }

    #[test]
    fn go_used_symbols_nested_selector() {
        // `pkg.A.B` surfaces only `A` on the package — the outer selector's
        // operand is a selector_expression, not the bound identifier.
        let syms =
            used_go("package main\nimport \"github.com/x/y\"\nfunc main() { y.Config.Field }");
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
        let src =
            "import _ from 'lodash';\nfunction apply(items) { items.forEach(i => _.merge(i)); }";
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
        let src =
            "from requests import get\nget('https://x')\ndef fetch():\n    get('https://y')\n";
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
        let src = "import os\nfrom requests import get\ndef a():\n    os.getcwd()\ndef b():\n    get('x')\n";
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
            b"package main\nimport \"github.com/spf13/cobra\"\nfunc run() { cobra.Execute() }"
                .to_vec(),
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
        let sites =
            functions_reaching("Symfony\\Component\\Console\\Application", "create", &files);
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
}
