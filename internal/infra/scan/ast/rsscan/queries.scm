; Tree-sitter queries for Rust dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes:
; - Rust call paths are usually scoped (e.g. `std::process::Command`).
;   We capture the whole scoped_identifier as @callee text and use
;   #match? with anchored regexes, so the same query catches:
;     Command::new(...)
;     process::Command::new(...)
;     std::process::Command::new(...)
;   Equivalent for the `tokio::process::Command::new(...)` async form.
; - Rust has no first-class `eval`. Dynamic code execution maps to
;   `libloading` (FFI dlopen), which is the closest equivalent.
; - Capability names match the suffix of domain.Capability.String().

;; ---- shell spawn -------------------------------------------------------

;; Command::new("sh") and friends — the canonical Rust way to exec.
;; Works for std::process::Command, tokio::process::Command, and any
;; async runtime that re-exports it.
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)Command::new$"))
  @cap.shell-spawn

;; std::os::unix::process::CommandExt::exec — replaces the current
;; process image. Caught both as a method call and a path call.
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "::CommandExt::exec$"))
  @cap.shell-spawn

;; libc::execv / execve / system — direct FFI shell-out
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "^libc::(execv|execve|execvp|execvpe|system|popen)$"))
  @cap.shell-spawn

;; nix::unistd::{execv,execve,...} — popular nix(crate) wrapper
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "^nix::unistd::(execv|execve|execvp|execvpe|exec)$"))
  @cap.shell-spawn

;; ---- dynamic eval (Rust analogue: dynamic library loading) -------------

;; libloading::Library::new — runtime-determined .so / .dll load,
;; closest Rust analogue to eval/exec.
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)Library::new$"))
  @cap.dynamic-eval

;; libloading::os::{unix,windows}::Library::new
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)os::(unix|windows)::Library::new$"))
  @cap.dynamic-eval

;; libc::dlopen / dlsym — direct FFI dynamic loading
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "^libc::(dlopen|dlsym)$"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; base64::decode / base64::decode_config — old API
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "^base64::(decode|decode_config|decode_engine)$"))
  @cap.base64-decode

;; engine.decode(...) — new API. Match the method name only;
;; over-fires on benign decode() calls but base64 is the dominant
;; usage in Rust malware so the false-positive rate is acceptable.
(call_expression
  function: (field_expression
    field: (field_identifier) @method)
  (#eq? @method "decode"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; reqwest::get / reqwest::blocking::get / reqwest::async_impl::get
;; and the popular HTTP crates' top-level helpers. The (?:...) group
;; allows for an optional submodule (commonly `blocking` or `async_impl`).
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "^(reqwest|ureq|attohttpc|surf|isahc)(::[a-z_]+)?::(get|post|put|delete|patch|head)$"))
  @cap.net-egress

;; reqwest::Client::new and reqwest::blocking::Client::new (typestate
;; entry points). Same submodule allowance.
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "^(reqwest|hyper|isahc)(::[a-z_]+)?::Client::(new|builder)$"))
  @cap.net-egress

;; std::net::TcpStream::connect — raw socket egress
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)TcpStream::connect$"))
  @cap.net-egress

;; tokio::net::TcpStream::connect — async raw socket
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)tokio::net::TcpStream::connect$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; std::env::var / env::var with a string-literal arg. Capture the
;; literal so the credential-shaped-name filter applies at scoring time.
(call_expression
  function: (scoped_identifier) @callee
  arguments: (arguments
    (string_literal (string_content) @env_var))
  (#match? @callee "(^|::)env::(var|var_os)$"))

;; ---- fs write outside root --------------------------------------------

;; std::fs::write — single-call write
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)fs::write$"))
  @cap.fs-write-outside-root

;; std::fs::copy / rename — relocates content elsewhere on disk
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)fs::(copy|rename|hard_link)$"))
  @cap.fs-write-outside-root

;; File::create — opens a file for writing
(call_expression
  function: (scoped_identifier) @callee
  (#match? @callee "(^|::)File::create$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------
;; http(s)://NNN.NNN.NNN.NNN inside a string literal. Same convention
;; as the JS / Python / Ruby scanners.

(string_literal (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
