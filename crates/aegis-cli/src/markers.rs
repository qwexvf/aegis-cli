//! Sentinel-delimited blocks in files we do not own.
//!
//! Both the git pre-commit hook and the shell rc snippet need to add, replace
//! and remove *their own* block in a file the user also edits, without ever
//! touching the rest of it. Extracted from `hook.rs` so the two share one
//! tested implementation rather than diverging.

/// Replace the marked block if present, otherwise append it.
///
/// Pure so the marker handling is testable without touching a filesystem.
pub(crate) fn inject(existing: &str, body: &str, start_marker: &str, end_marker: &str) -> String {
    let body = if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    };
    let block = format!("{start_marker}\n{body}{end_marker}\n");

    if let Some(start) = existing.find(start_marker) {
        if let Some(rel_end) = existing[start..].find(end_marker) {
            let mut end = start + rel_end + end_marker.len();
            if existing[end..].starts_with('\n') {
                end += 1;
            }
            return format!("{}{}{}", &existing[..start], block, &existing[end..]);
        }
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);
    out
}

/// Remove the marked block. `None` when there was nothing of ours to remove,
/// so callers can report "not installed" rather than rewriting the file — and,
/// for an rc file, rather than touching it at all.
pub(crate) fn strip(existing: &str, start_marker: &str, end_marker: &str) -> Option<String> {
    let start = existing.find(start_marker)?;
    let rel_end = existing[start..].find(end_marker)?;
    let mut end = start + rel_end + end_marker.len();
    if existing[end..].starts_with('\n') {
        end += 1;
    }
    Some(format!("{}{}", &existing[..start], &existing[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "# >>> start >>>";
    const E: &str = "# <<< end <<<";

    #[test]
    fn inject_is_idempotent_and_preserves_surroundings() {
        let out = inject("before\n", "BODY", S, E);
        assert!(out.starts_with("before\n"));
        assert!(out.contains("BODY"));

        // Injecting again replaces rather than stacking.
        let twice = inject(&out, "BODY2", S, E);
        assert_eq!(twice.matches(S).count(), 1);
        assert!(twice.contains("BODY2"));
        assert!(!twice.contains("BODY\n"));
        assert!(twice.starts_with("before\n"));
    }

    #[test]
    fn strip_removes_only_our_block() {
        let out = inject("keep-before\n", "BODY", S, E);
        let out = format!("{out}keep-after\n");
        let stripped = strip(&out, S, E).unwrap();
        assert_eq!(stripped, "keep-before\nkeep-after\n");
    }

    #[test]
    fn strip_reports_when_nothing_is_ours() {
        assert!(strip("unrelated\n", S, E).is_none());
    }
}
