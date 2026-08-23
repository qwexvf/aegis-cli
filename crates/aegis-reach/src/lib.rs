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
    /// C# (`tree-sitter-c-sharp`).
    CSharp,
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

/// Parse C# source and return every `using` directive it declares.
///
/// A parse failure yields an empty vec — never panics.
pub fn extract_imports_csharp(source: &[u8]) -> Vec<Import> {
    extract_with(Language::CSharp, source)
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
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
    };
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    // No depth guard here: the import walk is iterative (`preorder`/`walk*`) and
    // safe at any nesting. Only the recursive used-symbol/call-graph/site
    // walkers below need the guard.

    let mut imports = Vec::new();
    match lang {
        Language::JavaScript => walk(tree.root_node(), source, &mut imports),
        Language::Python => walk_python(tree.root_node(), source, &mut imports),
        Language::Go => walk_go(tree.root_node(), source, &mut imports),
        Language::Php => walk_php(tree.root_node(), source, &mut imports),
        Language::Ruby => walk_ruby(tree.root_node(), source, &mut imports),
        Language::Rust => walk_rust(tree.root_node(), source, &mut imports),
        Language::Java => walk_java(tree.root_node(), source, &mut imports),
        Language::CSharp => walk_csharp(tree.root_node(), source, &mut imports),
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
    } else if lower.ends_with(".cs") {
        Some(Language::CSharp)
    } else {
        None
    }
}

/// Depth past which a source file is treated as pathological and skipped.
/// Real code (even generated bundles) sits far under this; the used-symbol,
/// call-graph, and symbol-site walkers below still recurse one frame per AST
/// level, so this bound keeps an adversarially-nested file from overflowing the
/// stack. The import pass uses the iterative [`preorder`] and needs no guard.
const MAX_AST_DEPTH: usize = 500;

/// Whether any node in the tree sits deeper than [`MAX_AST_DEPTH`]. Iterative
/// (constant stack), so the check itself can't overflow.
fn tree_too_deep(root: Node) -> bool {
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_AST_DEPTH {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, depth + 1));
        }
    }
    false
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

/// Candidate top-level import names for a PyPI **distribution** name, for
/// consumer-side reachability matching (`classify`, engine `dep_reachability`).
///
/// The import name a project writes (`import yaml`) frequently differs from the
/// distribution name in the lockfile (`PyYAML`). `dep_key_python` normalizes the
/// *import* side; this normalizes the *distribution* side to the set of names it
/// could be imported as, so the two meet. Matching against ANY candidate errs
/// toward `Used` — the security-safe direction: a missed mapping must never
/// downgrade a live advisory on a dep that is actually imported.
///
/// Sources, in order: a curated table for the well-known mismatches (the
/// authoritative map lives in each wheel's `top_level.txt`, unavailable to an
/// offline lockfile scan), then normalized fallbacks (PEP 503 lowercase, and
/// `-`/`.` → `_`). The raw name is always included.
pub fn pypi_import_candidates(dist: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };
    push(dist.to_string());

    // Curated dist → import-top-level for the common non-matching cases.
    let lower = dist.to_ascii_lowercase();
    if let Some(mapped) = match lower.as_str() {
        "pyyaml" => Some("yaml"),
        "beautifulsoup4" => Some("bs4"),
        "pillow" => Some("PIL"),
        "python-dateutil" => Some("dateutil"),
        "python-dotenv" => Some("dotenv"),
        "scikit-learn" => Some("sklearn"),
        "scikit-image" => Some("skimage"),
        "opencv-python" => Some("cv2"),
        "opencv-python-headless" => Some("cv2"),
        "msgpack-python" => Some("msgpack"),
        "attrs" => Some("attr"),
        "pymysql" => Some("pymysql"),
        "protobuf" => Some("google"),
        "google-cloud-storage" => Some("google"),
        "typing-extensions" => Some("typing_extensions"),
        _ => None,
    } {
        push(mapped.to_string());
    }

    // Normalized fallbacks for the merely-cased / punctuation-swapped cases
    // (`Django` → `django`, `python-dateutil` → `python_dateutil`).
    push(lower.clone());
    push(lower.replace(['-', '.'], "_"));
    out
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

/// PHP dep key — always empty, a documented limitation rather than a stub.
///
/// Dep-level reachability needs a `use Foo\Bar` namespace mapped to a Composer
/// `vendor/package`. That mapping lives only in each dependency's composer.json
/// PSR-4 `autoload`, which isn't present offline (no `composer install`), and
/// the top namespace segment is NOT reliably the vendor (`GuzzleHttp` →
/// `guzzlehttp/guzzle`, `Doctrine\ORM` → `doctrine/orm`). A heuristic here would
/// silently mis-match — for a security downgrade that means wrongly suppressing
/// a live advisory — so PHP is intentionally not keyed at the dep level, and
/// Packagist is not `reachability_eligible` in the `ci` gate. The PHP
/// used-symbol pass still works: it matches the verbatim namespace `module`, a
/// separate axis that needs no package mapping. Mirrors depusage's PHP `DepKey`.
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
// Rust used-symbols
// ---------------------------------------------------------------------------

/// One resolved `use` leaf: the crate dep key it roots at, the imported item
/// (last path segment), and the local name it binds (the `as` alias when
/// present, else the item).
struct RustBinding {
    module: String,
    symbol: String,
    local: String,
}

/// Expand a Rust use-tree's text into flat `(full_path, alias)` leaves.
/// Handles nested brace groups (`a::{b, c::d}`) and per-leaf `as` aliases
/// (`a::b as x`). A `*` wildcard leaf is kept verbatim so the caller can treat
/// it as a namespace root. Text-based on purpose — robust across the several
/// tree-sitter node shapes a use tree can take.
fn expand_rust_use(tree: &str) -> Vec<(String, Option<String>)> {
    expand_rust_use_depth(tree, 0)
}

/// Cap on use-tree brace nesting. Real code never approaches this; the bound
/// stops adversarial/error-recovery text like `a::{{{{…}}}}` from overflowing
/// the stack.
const MAX_USE_TREE_DEPTH: usize = 64;

fn expand_rust_use_depth(tree: &str, depth: usize) -> Vec<(String, Option<String>)> {
    let tree = tree.trim();
    let no_group = || {
        // A single path, optionally `path as alias`.
        let (path, alias) = match tree.split_once(" as ") {
            Some((p, a)) => (p.trim().to_string(), Some(a.trim().to_string())),
            None => (tree.to_string(), None),
        };
        vec![(path, alias)]
    };
    if depth > MAX_USE_TREE_DEPTH {
        return no_group();
    }
    let Some(open) = tree.find('{') else {
        return no_group();
    };
    // The closing brace must come *after* the opening one. Malformed input
    // (error-recovery text, `a::}{b`) can put `}` first; treat as no group
    // rather than slicing a reversed range (which panics).
    let Some(close) = tree.rfind('}').filter(|&c| c > open) else {
        return no_group();
    };
    // Match the group to its closing brace and split the inner list on
    // top-level commas (nested groups keep their commas).
    let prefix = tree[..open].trim_end().trim_end_matches("::");
    let inner = &tree[open + 1..close];
    let mut out = Vec::new();
    for item in split_top_level_commas(inner) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        for (sub, alias) in expand_rust_use_depth(item, depth + 1) {
            let full = if prefix.is_empty() {
                sub
            } else if sub.is_empty() {
                prefix.to_string()
            } else {
                format!("{prefix}::{sub}")
            };
            out.push((full, alias));
        }
    }
    out
}

/// Split on commas that sit outside any `{}` nesting.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '{' => {
                depth += 1;
                cur.push(c);
            }
            '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Parse Rust source and return every use of an imported crate symbol.
///
/// Two passes: collect `use` bindings (local name → crate + imported item),
/// then walk usage sites and correlate. Two site shapes are recognized,
/// mirroring the Go pass's package-selector model:
///
/// - `local::Sym` (member access on a bound module/type) → `(crate, Sym)`.
/// - `crate::Sym...` (a full path rooted at an imported crate) → `(crate, Sym)`.
/// - `f(...)` where `f` is a bound item local → `(crate, item)`.
///
/// Bare type-position uses (`T: Serialize`, `#[derive(Serialize)]`) are not
/// counted — the pass stays call/path-anchored to avoid matching same-named
/// locals. `crate`/`self`/`super`/`std`/`core`/`alloc` roots bind nothing.
/// A parse failure yields an empty vec.
pub fn extract_used_symbols_rust(source: &[u8]) -> Vec<UsedSymbol> {
    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

    // Bindings by local name, and the set of imported crate dep keys.
    let mut bindings: HashMap<String, RustBinding> = HashMap::new();
    let mut crate_roots: HashSet<String> = HashSet::new();
    collect_rust_use_bindings(tree.root_node(), source, &mut bindings, &mut crate_roots);
    if bindings.is_empty() && crate_roots.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    collect_rust_uses(tree.root_node(), source, &bindings, &crate_roots, &mut out);
    out
}

fn collect_rust_use_bindings(
    node: Node,
    body: &[u8],
    bindings: &mut HashMap<String, RustBinding>,
    crate_roots: &mut HashSet<String>,
) {
    preorder(node, &mut |n| {
        if n.kind() != "use_declaration" {
            return;
        }
        let Some(arg) = n.child_by_field_name("argument") else {
            return;
        };
        let Ok(text) = arg.utf8_text(body) else {
            return;
        };
        for (path, alias) in expand_rust_use(text) {
            let module = dep_key_rust(&path);
            if module.is_empty() {
                continue;
            }
            crate_roots.insert(module.clone());
            let leaf = path.rsplit("::").next().unwrap_or(&path).trim();
            if leaf == "*" || leaf.is_empty() {
                continue; // wildcard / bare crate: no concrete local symbol
            }
            let local = alias.unwrap_or_else(|| leaf.to_string());
            bindings.insert(
                local.clone(),
                RustBinding {
                    module,
                    symbol: leaf.to_string(),
                    local,
                },
            );
        }
    });
}

fn collect_rust_uses(
    node: Node,
    body: &[u8],
    bindings: &HashMap<String, RustBinding>,
    crate_roots: &HashSet<String>,
    out: &mut Vec<UsedSymbol>,
) {
    // Don't descend into import declarations — their paths aren't uses.
    if matches!(node.kind(), "use_declaration" | "extern_crate_declaration") {
        return;
    }
    if node.kind() == "scoped_identifier" {
        if let Ok(text) = node.utf8_text(body) {
            let segs: Vec<&str> = text.split("::").map(|s| s.trim()).collect();
            if segs.len() >= 2 && !segs[0].is_empty() {
                let head = segs[0];
                let second = segs[1].to_string();
                let line = node.start_position().row + 1;
                if let Some(b) = bindings.get(head) {
                    // `local::Sym` — member access on a bound module/type.
                    out.push(UsedSymbol {
                        module: b.module.clone(),
                        symbol: second,
                        line,
                    });
                } else {
                    // `crate::Sym...` — a full path rooted at an imported crate.
                    let m = dep_key_rust(head);
                    if !m.is_empty() && crate_roots.contains(&m) {
                        out.push(UsedSymbol {
                            module: m,
                            symbol: second,
                            line,
                        });
                    }
                }
            }
        }
        // A scoped_identifier's children are just path segments — no deeper
        // uses to find.
        return;
    }
    if node.kind() == "call_expression" {
        // Unwrap a turbofish call (`from_str::<i32>()` parses as a
        // `generic_function` wrapping the callee) to reach the identifier.
        let mut callee = node.child_by_field_name("function");
        if let Some(c) = callee {
            if c.kind() == "generic_function" {
                callee = c.child_by_field_name("function");
            }
        }
        if let Some(func) = callee {
            if func.kind() == "identifier" {
                if let Ok(name) = func.utf8_text(body) {
                    if let Some(b) = bindings.get(name) {
                        if b.local == name {
                            out.push(UsedSymbol {
                                module: b.module.clone(),
                                symbol: b.symbol.clone(),
                                line: func.start_position().row + 1,
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_uses(child, body, bindings, crate_roots, out);
    }
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
// C#
// ---------------------------------------------------------------------------

/// Walk a C# tree, converting each `using_directive` into an [`Import`].
/// Covers plain (`using System.Text.Json;`), `global using`, `static`
/// (`using static System.Math;`), and alias (`using J = System.Text.Json;`)
/// forms — all static imports.
fn walk_csharp(node: Node, body: &[u8], out: &mut Vec<Import>) {
    preorder(node, &mut |n| {
        if n.kind() == "using_directive" {
            if let Some(imp) = parse_csharp_using(n, body) {
                out.push(imp);
            }
        }
    });
}

/// Turn a `using_directive` into one [`Import`]. The namespace/type path is the
/// last `qualified_name`/`identifier` child (an alias's `X =` prefix and the
/// `using`/`global`/`static` keywords are skipped); a `static` keyword marks
/// the member-import form. The dep key is the namespace.
fn parse_csharp_using(node: Node, body: &[u8]) -> Option<Import> {
    let mut name: Option<String> = None;
    let mut is_static = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // The namespace/type path. For an alias (`J = System.X`) the target
            // path is the last such node, so keep overwriting.
            "qualified_name" | "identifier" => {
                name = child.utf8_text(body).ok().map(str::to_string);
            }
            "static" => is_static = true,
            _ => {}
        }
    }
    let name = name?;
    if name.is_empty() {
        return None;
    }
    // A static using imports a type's members (`using static System.Math`);
    // strip the trailing type so the dep key resolves the namespace.
    let key_input = if is_static {
        name.rsplit_once('.').map(|(ns, _)| ns).unwrap_or(&name)
    } else {
        &name
    };
    Some(Import {
        dep_key: dep_key_csharp(key_input),
        module: name.clone(),
        kind: ImportKind::Static,
        line: node.start_position().row + 1,
    })
}

/// Dep key for a C# namespace. Unlike Java, the .NET base-class-library
/// namespaces (`System.*`) are NOT filtered — many ship as real NuGet packages
/// (`System.Text.Json`, `System.Text.Encodings.Web`), so dropping them would
/// miss live deps. The whole namespace is kept; the consumer matches it against
/// package names by dotted prefix (a package and its namespace share a root,
/// e.g. package `Newtonsoft.Json` ⊇ `using Newtonsoft.Json.Linq`).
pub fn dep_key_csharp(raw: &str) -> String {
    let raw = raw.trim();
    // `global` / `alias` artifacts shouldn't reach here, but guard anyway.
    if raw.is_empty() || raw == "static" || raw == "global" {
        return String::new();
    }
    raw.to_string()
}

mod used_symbols;
pub use used_symbols::*;
mod attribution;
pub use attribution::*;

#[cfg(test)]
mod tests;
