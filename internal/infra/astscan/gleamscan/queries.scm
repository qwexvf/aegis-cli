; Tree-sitter queries for Gleam dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via capabilityFor().
;
; Gleam is a type-safe language: no direct syscalls or eval. Dangerous
; patterns are:
;   1. @external / external fn — FFI bypasses all safety guarantees
;   2. Import of network/file/os modules — surface-level reachability
;   3. Raw IP literals in strings
;
; Import-based detection is conservative (import ≠ call) but reliable:
; a package that imports gleam/http almost certainly makes HTTP requests.

;; ---- dynamic eval (FFI / external function) ----------------------------

;; @external(erlang, ...) or @external(javascript, ...) — new syntax
;; Any @external bypasses Gleam's type safety; flag as dynamic-eval.
(function
  (attribute
    name: (identifier) @_attr)
  (#eq? @_attr "external"))
  @cap.dynamic-eval

;; external fn — old syntax, removed in v0.30 but still in the wild
(external_function) @cap.dynamic-eval

;; ---- net egress --------------------------------------------------------

;; Import of HTTP client modules
(import
  module: (module) @mod
  (#match? @mod "^(gleam/http|gleam/httpc|gleam_http)"))
  @cap.net-egress

;; gleam_erlang/port — spawns OS processes / sockets
(import
  module: (module) @mod
  (#match? @mod "^gleam_erlang/port"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; gleam_erlang/os — provides os.get_env
(import
  module: (module) @mod
  (#match? @mod "^gleam_erlang/os"))
  @cap.env-read

;; ---- fs write outside root --------------------------------------------

;; gleam_erlang/file or simplifile — file system access
(import
  module: (module) @mod
  (#match? @mod "^(gleam_erlang/file|simplifile)"))
  @cap.fs-write-outside-root

;; ---- shell spawn -------------------------------------------------------

;; gleam_erlang/atom + port are the combo used for OS command execution
(import
  module: (module) @mod
  (#match? @mod "^(gleam_erlang/atom)"))
  @cap.shell-spawn

;; ---- raw IP literal ----------------------------------------------------

(string) @ip_str
  (#match? @ip_str "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
  @cap.raw-ip-literal
