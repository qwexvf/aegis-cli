//! Binary-dropper detector. Port of `binary_dropper.go` +
//! `check_binary_dropper.go`.
//!
//! Flags [`Capability::BinaryDropper`] when a package ships a native
//! executable or platform-specific script outside the locations its
//! ecosystem legitimately uses for compiled artifacts. Pure string ops —
//! no regex, works fully offline.

use aegis_domain::{Capability, Ecosystem};

use crate::NormalizedPackage;

/// True when the filename's extension is on the "native binary or
/// platform script" list. Mirrors Go's `path.Ext`: the extension is the
/// suffix after the final dot in the basename (last path element).
fn is_suspicious_binary(filename: &str) -> bool {
    let base = filename.rsplit_once('/').map_or(filename, |(_, b)| b);
    let ext = match base.rsplit_once('.') {
        Some((_, ext)) => ext,
        None => return false,
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "exe" | "msi" | "bat" | "cmd" | "dll" | "so" | "dylib" | "scpt" | "applescript" | "ps1"
    )
}

/// True when a (ecosystem, filename) pair matches the canonical "this is
/// supposed to be a binary" packaging convention — so the heuristic
/// should NOT fire. Carve-outs are intentionally tight.
fn is_expected_native_path(eco: Option<Ecosystem>, filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    match eco {
        Some(Ecosystem::PyPI) => {
            // CPython ABI-tagged extensions, .abi3.so, and .pyd (Windows)
            // — how PyPI wheels legitimately ship C extensions.
            if lower.contains(".cpython-") && lower.ends_with(".so") {
                return true;
            }
            if lower.ends_with(".abi3.so") {
                return true;
            }
            if lower.ends_with(".pyd") {
                return true;
            }
            // manylinux bundled-library conventions: <pkg>/.libs/ (auditwheel)
            // and <pkg>/_vendor/.
            lower.contains("/.libs/") || lower.contains("/_vendor/")
        }
        // crates.io & npm: no legitimate carve-out. Pre-compiled native
        // artifacts in a crate are the malware pattern; npm binaries
        // belong to allowlisted toolchain packages, not a builtin rule.
        _ => false,
    }
}

/// Flags packages that ship a native executable or platform-specific
/// script outside the expected locations for their ecosystem.
pub fn check_binary_dropper(pkg: &NormalizedPackage) -> Vec<Capability> {
    for fpath in pkg.files.keys() {
        if is_suspicious_binary(fpath) && !is_expected_native_path(pkg.ecosystem_name, fpath) {
            return vec![Capability::BinaryDropper];
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: Ecosystem, files: &[&str]) -> NormalizedPackage {
        let mut p = NormalizedPackage::new("t", eco);
        for f in files {
            p = p.with_file(*f, Vec::new());
        }
        p
    }

    #[test]
    fn exe_in_npm_flags() {
        assert_eq!(
            check_binary_dropper(&pkg(Ecosystem::Npm, &["package.json", "tools/install.exe"])),
            vec![Capability::BinaryDropper]
        );
    }

    #[test]
    fn dll_ps1_scpt_in_npm_flag() {
        for f in ["native.dll", "setup.ps1", "helper.scpt"] {
            assert_eq!(
                check_binary_dropper(&pkg(Ecosystem::Npm, &[f, "index.js"])),
                vec![Capability::BinaryDropper],
                "{f}"
            );
        }
    }

    #[test]
    fn case_insensitive_ext() {
        assert_eq!(
            check_binary_dropper(&pkg(Ecosystem::Npm, &["x.EXE"])),
            vec![Capability::BinaryDropper]
        );
    }

    #[test]
    fn pure_js_no_signal() {
        assert!(check_binary_dropper(&pkg(
            Ecosystem::Npm,
            &["index.js", "package.json", "README.md"]
        ))
        .is_empty());
    }

    #[test]
    fn pypi_native_carveouts() {
        let ok = [
            "pillow/_imaging.cpython-310-x86_64-linux-gnu.so",
            "cryptography/_rust.abi3.so",
            "numpy/_core.pyd",
            "numpy/.libs/libopenblas.so.0",
        ];
        for f in ok {
            assert!(
                check_binary_dropper(&pkg(Ecosystem::PyPI, &[f])).is_empty(),
                "{f} should be carved out"
            );
        }
    }

    #[test]
    fn pypi_so_outside_expected_flags() {
        assert_eq!(
            check_binary_dropper(&pkg(Ecosystem::PyPI, &["ultralytics/data/.cache/xmrig.so"])),
            vec![Capability::BinaryDropper]
        );
    }

    #[test]
    fn pypi_exe_flags() {
        assert_eq!(
            check_binary_dropper(&pkg(Ecosystem::PyPI, &["pkg/payload.exe"])),
            vec![Capability::BinaryDropper]
        );
    }

    #[test]
    fn crates_native_flags() {
        for f in ["native/payload.so", "vendor/win.dll"] {
            assert_eq!(
                check_binary_dropper(&pkg(Ecosystem::Crates, &[f])),
                vec![Capability::BinaryDropper],
                "{f}"
            );
        }
    }

    #[test]
    fn crates_pure_source_no_signal() {
        assert!(
            check_binary_dropper(&pkg(Ecosystem::Crates, &["src/lib.rs", "Cargo.toml"])).is_empty()
        );
    }

    #[test]
    fn empty_source_no_signal() {
        assert!(check_binary_dropper(&NormalizedPackage::new("t", Ecosystem::Npm)).is_empty());
    }
}
