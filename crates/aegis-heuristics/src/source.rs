//! Shared "is this an analyzable source file?" predicate. Port of
//! `isAnalyzableSource` (source_patterns.go).

/// True when `filename`'s extension marks it as source a content-scanning
/// heuristic should read. Covers JS/TS plus the ecosystems aegis scans.
pub(crate) fn is_analyzable_source(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    let ext = match lower.rsplit_once('.') {
        Some((_, e)) => e,
        None => return false,
    };
    matches!(
        ext,
        // JS / TS
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx"
        // Python
        | "py" | "pyi" | "pyx"
        // Ruby
        | "rb" | "gemspec"
        // Rust / Go / JVM / .NET / PHP
        | "rs" | "go" | "java" | "php" | "phtml" | "cs" | "csx"
        // R / CRAN
        | "r" | "rmd" | "rnw"
        // Haskell / Hackage
        | "hs" | "lhs"
        // Perl / CPAN
        | "pl" | "pm"
        // Dart / Swift
        | "dart" | "swift"
    )
}
