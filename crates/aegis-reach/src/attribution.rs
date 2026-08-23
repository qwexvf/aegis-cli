//! Call-graph and symbol-site attribution (which project function reaches a
//! dependency symbol), per language. Split out of lib.rs.

use super::*;

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
    if tree_too_deep(tree.root_node()) {
        return Vec::new();
    }

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
