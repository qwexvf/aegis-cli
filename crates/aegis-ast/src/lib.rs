//! AST capability scanner. Port of `internal/infra/scan/ast`.
//!
//! Uses tree-sitter with **native Rust grammar crates** — no CGO, no C
//! toolchain (the headline win of the migration). Each `.scm` query is
//! ported verbatim from the Go tree; `@cap.<name>` captures map to a
//! domain [`Capability`], `@env_var` captures record read env-var names.
//!
//! Each grammar sits behind a per-language Cargo feature.

use aegis_domain::Capability;

// tree-sitter is a hard dependency, so the generic scanner always compiles.
mod scanner;
pub use scanner::GrammarScanner;

#[cfg(feature = "cocoapods")]
pub mod cocoapods;
#[cfg(feature = "csharp")]
pub mod csharp;
#[cfg(feature = "dart")]
pub mod dart;
#[cfg(feature = "gleam")]
pub mod gleam;
#[cfg(feature = "go")]
pub mod go;
#[cfg(feature = "haskell")]
pub mod haskell;
#[cfg(feature = "java")]
pub mod java;
#[cfg(feature = "js")]
pub mod js;
#[cfg(feature = "js")]
mod js_taint;
#[cfg(feature = "lua")]
pub mod lua;
#[cfg(feature = "php")]
pub mod php;
#[cfg(feature = "py")]
pub mod py;
#[cfg(feature = "ruby")]
pub mod ruby;
#[cfg(feature = "rust")]
pub mod rust;

/// One evidence record: where a capability was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub capability: Capability,
    pub path: String,
    pub line: usize,
    pub snippet: String,
}

/// Accumulated output of scanning one or more files. Mirrors
/// `ast.Findings`.
#[derive(Debug, Clone, Default)]
pub struct Findings {
    capabilities: Vec<Capability>,
    env_reads: Vec<String>,
    /// when true, per-capability [`Evidence`] is recorded.
    pub collect_evidence: bool,
    evidence: Vec<Evidence>,
}

impl Findings {
    pub fn new(collect_evidence: bool) -> Self {
        Findings {
            collect_evidence,
            ..Default::default()
        }
    }

    /// Record a capability (deduped).
    pub fn add_capability(&mut self, c: Capability) {
        if !self.capabilities.contains(&c) {
            self.capabilities.push(c);
        }
    }

    /// Record a read env-var name (deduped).
    pub fn add_env_read(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.env_reads.contains(&name) {
            self.env_reads.push(name);
        }
    }

    pub fn add_evidence(&mut self, c: Capability, path: &str, line: usize, snippet: String) {
        self.evidence.push(Evidence {
            capability: c,
            path: path.to_string(),
            line,
            snippet,
        });
    }

    /// Detected capabilities, sorted for deterministic output.
    pub fn capabilities(&self) -> Vec<Capability> {
        let mut c = self.capabilities.clone();
        c.sort();
        c
    }

    pub fn env_reads(&self) -> &[String] {
        &self.env_reads
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Fold another `Findings` into this one (deduping). Used to combine
    /// per-file results from a parallel scan.
    pub fn merge(&mut self, other: Findings) {
        for c in other.capabilities {
            self.add_capability(c);
        }
        for e in other.env_reads {
            self.add_env_read(e);
        }
        self.evidence.extend(other.evidence);
    }
}

/// A per-language AST analyzer. Mirrors `ast.LanguageScanner`.
///
/// `Send + Sync` so a compiled scanner can be shared read-only across a
/// rayon thread pool (the query is immutable; parser/cursor are created
/// per call inside `analyze_file`).
pub trait LanguageScanner: Send + Sync {
    /// Parse `body` and record capabilities/env-reads into `findings`.
    fn analyze_file(&self, path: &str, body: &[u8], findings: &mut Findings);
}

/// Build the scanner for a filename's language, or None when no
/// compiled-in grammar handles that extension.
#[allow(unused_variables)]
pub fn scanner_for(filename: &str) -> Option<Box<dyn LanguageScanner>> {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())?;
    match ext.as_str() {
        #[cfg(feature = "js")]
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "cts" | "mts" => js::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "py")]
        "py" | "pyi" | "pyx" => py::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "ruby")]
        "rb" | "gemspec" => ruby::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "rust")]
        "rs" => rust::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "go")]
        "go" => go::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "php")]
        "php" | "phtml" => php::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "csharp")]
        "cs" | "csx" => csharp::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "java")]
        "java" => java::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "haskell")]
        "hs" | "lhs" => haskell::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "lua")]
        "lua" => lua::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "gleam")]
        "gleam" => gleam::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "dart")]
        "dart" => dart::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        #[cfg(feature = "cocoapods")]
        "podspec" => cocoapods::scanner()
            .ok()
            .map(|s| Box::new(s) as Box<dyn LanguageScanner>),
        _ => None,
    }
}
