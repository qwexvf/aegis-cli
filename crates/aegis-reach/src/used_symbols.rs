//! Used-symbol extraction (which imported symbols a project actually
//! references), per language. Split out of lib.rs.

use super::*;

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
pub(crate) struct JsBinding {
    pub(crate) module: String,
    pub(crate) symbol: String,
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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
/// `.php/.phtml` through the PHP one, `.rs` through the Rust one; any other
/// extension is skipped. Ruby has no used-symbol pass by design
/// (`require`/`gem` bind no local — see the module docs), so `.rb` files
/// contribute nothing here. A file whose usages don't reference `dep_key`
/// contributes nothing.
pub fn used_symbols_of(dep_key: &str, files: &[(String, Vec<u8>)]) -> HashSet<String> {
    let mut out = HashSet::new();
    for (path, bytes) in files {
        let uses = match language_for(path) {
            Some(Language::JavaScript) => extract_used_symbols(bytes),
            Some(Language::Python) => extract_used_symbols_python(bytes),
            Some(Language::Go) => extract_used_symbols_go(bytes),
            Some(Language::Php) => extract_used_symbols_php(bytes),
            Some(Language::Rust) => extract_used_symbols_rust(bytes),
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
pub(crate) fn symbol_sites_for(path: &str, bytes: &[u8]) -> Vec<SymbolSite> {
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
pub(crate) fn call_graph_for(path: &str, bytes: &[u8]) -> Vec<CallNode> {
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
pub(crate) fn used_symbol_module(module: &str) -> String {
    let key = dep_key(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Recursively walk the JS tree, recording local bindings from `import`
/// statements and `const x = require('m')` declarators.
pub(crate) fn collect_js_bindings(node: Node, body: &[u8], out: &mut HashMap<String, JsBinding>) {
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
pub(crate) fn js_bindings_from_import(
    node: Node,
    body: &[u8],
    out: &mut HashMap<String, JsBinding>,
) {
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
pub(crate) fn js_binding_from_require(
    node: Node,
    body: &[u8],
    out: &mut HashMap<String, JsBinding>,
) {
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
pub(crate) fn js_binding(module: &str, symbol: &str) -> JsBinding {
    JsBinding {
        module: module.to_string(),
        symbol: symbol.to_string(),
    }
}

/// Recursively walk the JS tree, correlating member/call usages against
/// the resolved bindings and pushing matches into `out`.
pub(crate) fn collect_js_uses(
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
pub(crate) struct PyBinding {
    pub(crate) module: String,
    pub(crate) symbol: String,
}

/// One import's binding-relevant shape, mirroring the depusage
/// `extract.Import` fields (`Symbols` / `Aliases`) that the Rust
/// [`Import`] drops. `raw_module` is the verbatim dotted path (needed for
/// the last-segment local of a whole-module import); `module` is its
/// dep-key form (or verbatim when it doesn't normalize). `aliases` is a
/// list of `(local_alias, canonical)` pairs where `canonical` is `"*"`
/// for an aliased whole-module import.
pub(crate) struct PyImportInfo {
    pub(crate) raw_module: String,
    pub(crate) module: String,
    pub(crate) symbols: Vec<String>,
    pub(crate) aliases: Vec<(String, String)>,
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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
pub(crate) fn used_symbol_module_python(module: &str) -> String {
    let key = dep_key_python(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Last dotted segment of a module path (`os.path` → `path`, `os` →
/// `os`). Port of depusage's `lastDotSegment`.
pub(crate) fn last_dot_segment(s: &str) -> &str {
    match s.rfind('.') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Recursively walk a Python tree, collecting one [`PyImportInfo`] per
/// imported module from `import` and `from ... import` statements.
/// Dynamic `__import__` / `importlib.import_module` calls carry no
/// symbols or aliases and so bind nothing — they are skipped here.
pub(crate) fn collect_py_import_infos(node: Node, body: &[u8], out: &mut Vec<PyImportInfo>) {
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
pub(crate) fn py_import_infos_from_statement(node: Node, body: &[u8], out: &mut Vec<PyImportInfo>) {
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
pub(crate) fn py_star_info(raw_module: &str, alias: Option<&str>) -> PyImportInfo {
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
pub(crate) fn py_import_info_from_from(node: Node, body: &[u8]) -> Option<PyImportInfo> {
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
pub(crate) fn build_py_bindings(imports: &[PyImportInfo]) -> HashMap<String, PyBinding> {
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
pub(crate) fn collect_py_uses(
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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
pub(crate) fn used_symbol_module_go(module: &str) -> String {
    let key = dep_key_go(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Last slash segment of an import path (`github.com/spf13/cobra` →
/// `cobra`, `fmt` → `fmt`). The conventional Go package-name heuristic.
pub(crate) fn last_slash_segment(s: &str) -> &str {
    match s.rfind('/') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Recursively walk the Go tree, recording one local-package → module
/// binding per `import_spec`.
pub(crate) fn collect_go_bindings(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
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
pub(crate) fn go_binding_from_spec(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
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
pub(crate) fn collect_go_uses(
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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
pub(crate) fn used_symbol_module_php(module: &str) -> String {
    let key = dep_key_php(module);
    if key.is_empty() {
        module.to_string()
    } else {
        key
    }
}

/// Last backslash segment of a PHP FQN (`Foo\Bar\Baz` → `Baz`). The
/// short class name a bare `use` binds into scope.
pub(crate) fn last_backslash_segment(s: &str) -> &str {
    match s.rfind('\\') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Recursively walk the PHP tree, recording one local-name → module
/// binding per `use` clause.
pub(crate) fn collect_php_bindings(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
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
pub(crate) fn php_bindings_from_use(node: Node, body: &[u8], out: &mut HashMap<String, String>) {
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
pub(crate) fn php_bind_clause(
    clause: Node,
    prefix: &str,
    body: &[u8],
    out: &mut HashMap<String, String>,
) {
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
pub(crate) fn php_use_clause_alias(clause: Node, body: &[u8]) -> Option<String> {
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
pub(crate) fn collect_php_uses(
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
pub(crate) fn php_push_use(
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
