package gleamscan

// CGO wrapper for the tree-sitter-gleam grammar. We compile the C source
// directly so the build works without a separately released Go binding that
// has correct include paths. The csrc/ directory contains a verbatim copy of
// the tree-sitter-gleam v1.1.0 C source (auto-generated, Apache-2.0).

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}/csrc
// #include "csrc/parser.c"
// #include "csrc/scanner.c"
import "C"

import "unsafe"

func gleamLanguage() unsafe.Pointer {
	return unsafe.Pointer(C.tree_sitter_gleam())
}
