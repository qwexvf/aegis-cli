; Tree-sitter queries for Lua dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via capabilityFor().
;
; Lua is a small dynamic language. Dangerous patterns are:
;   1. Direct exec / shell — os.execute, io.popen, vim.fn.system, ...
;   2. Direct eval — loadstring, load, loadfile, dofile, vim.api.nvim_exec
;   3. require of network / OS modules (import ≠ call, but reliable signal)
;   4. ffi.load / package.cpath — native binding load (folded into
;      install-hook-exec for v1 to avoid a new domain.Capability)
;   5. Raw IP literals in strings
;
; Note on AST shape: `variable` is a supertype in the grammar — it does
; not appear as a wrapping node in the parse tree. `os.execute` parses
; as `(function_call name: (dot_index_expression table: (identifier)
; field: (identifier)))` with no `variable` in between.

;; ---- shell spawn ------------------------------------------------------

;; os.execute(...)
(function_call
  name: (dot_index_expression
    table: (identifier) @_t
    field: (identifier) @_f)
  (#eq? @_t "os")
  (#eq? @_f "execute")) @cap.shell-spawn

;; io.popen(...)
(function_call
  name: (dot_index_expression
    table: (identifier) @_t
    field: (identifier) @_f)
  (#eq? @_t "io")
  (#eq? @_f "popen")) @cap.shell-spawn

;; vim.fn.system(...) and vim.fn.jobstart(...)
(function_call
  name: (dot_index_expression
    table: (dot_index_expression
      table: (identifier) @_root
      field: (identifier) @_mid)
    field: (identifier) @_leaf)
  (#eq? @_root "vim")
  (#eq? @_mid "fn")
  (#any-of? @_leaf "system" "jobstart")) @cap.shell-spawn

;; vim.system(...)
(function_call
  name: (dot_index_expression
    table: (identifier) @_t
    field: (identifier) @_f)
  (#eq? @_t "vim")
  (#eq? @_f "system")) @cap.shell-spawn

;; ---- dynamic eval -----------------------------------------------------

;; Bare global call: loadstring(...), load(...), loadfile(...), dofile(...)
(function_call
  name: (identifier) @_f
  (#any-of? @_f "loadstring" "load" "loadfile" "dofile")) @cap.dynamic-eval

;; vim.api.nvim_exec(...) / nvim_exec2(...) / nvim_exec_lua(...)
(function_call
  name: (dot_index_expression
    table: (dot_index_expression
      table: (identifier) @_root
      field: (identifier) @_mid)
    field: (identifier) @_leaf)
  (#eq? @_root "vim")
  (#eq? @_mid "api")
  (#any-of? @_leaf "nvim_exec" "nvim_exec2" "nvim_exec_lua")) @cap.dynamic-eval

;; ---- net egress -------------------------------------------------------

;; require("socket.http") / require("ssl.https") / require("http.request") /
;; require("resty.http")
(function_call
  name: (identifier) @_fn
  arguments: (arguments (string (string_content) @_mod))
  (#eq? @_fn "require")
  (#any-of? @_mod
    "socket.http" "socket.url"
    "ssl.https"
    "http.request" "http.client"
    "resty.http")) @cap.net-egress

;; vim.loop.new_tcp() / vim.uv.new_tcp() — luv socket creation
(function_call
  name: (dot_index_expression
    table: (dot_index_expression
      table: (identifier) @_root
      field: (identifier) @_mid)
    field: (identifier) @_leaf)
  (#eq? @_root "vim")
  (#any-of? @_mid "loop" "uv")
  (#any-of? @_leaf "new_tcp" "new_udp")) @cap.net-egress

;; ---- env read ---------------------------------------------------------

;; os.getenv(...)
(function_call
  name: (dot_index_expression
    table: (identifier) @_t
    field: (identifier) @_f)
  (#eq? @_t "os")
  (#eq? @_f "getenv")) @cap.env-read

;; vim.env.<NAME> access — read of any env var via vim.env table
(dot_index_expression
  table: (dot_index_expression
    table: (identifier) @_root
    field: (identifier) @_mid)
  (#eq? @_root "vim")
  (#eq? @_mid "env")) @cap.env-read

;; ---- fs-write-outside-root --------------------------------------------

;; io.open(...) — FP on read-mode opens is acceptable for v1
(function_call
  name: (dot_index_expression
    table: (identifier) @_t
    field: (identifier) @_f)
  (#eq? @_t "io")
  (#eq? @_f "open")) @cap.fs-write-outside-root

;; vim.fn.writefile(...)
(function_call
  name: (dot_index_expression
    table: (dot_index_expression
      table: (identifier) @_root
      field: (identifier) @_mid)
    field: (identifier) @_leaf)
  (#eq? @_root "vim")
  (#eq? @_mid "fn")
  (#eq? @_leaf "writefile")) @cap.fs-write-outside-root

;; ---- install-hook-exec (native binding load) --------------------------

;; ffi.load("native.so") — luajit/ffi native library load
(function_call
  name: (dot_index_expression
    table: (identifier) @_t
    field: (identifier) @_f)
  (#eq? @_t "ffi")
  (#eq? @_f "load")) @cap.install-hook-exec

;; package.cpath = ... — write to the C-library search path
(assignment_statement
  (variable_list
    (dot_index_expression
      table: (identifier) @_t
      field: (identifier) @_f))
  (#eq? @_t "package")
  (#eq? @_f "cpath")) @cap.install-hook-exec

;; ---- plugin-spec build hook -------------------------------------------

;; `build = "<shell-string>"` field inside a plugin spec table. Used by
;; lazy.nvim / packer.nvim / vim.pack to declare a post-install shell
;; command. Captured as @build-string so the Go scanner can pass the
;; body to heuristics.ScriptMatchesMalwarePattern — same matcher that
;; flags `curl | sh` in npm scripts and `build.rs` payloads. The Go
;; side only emits install-hook-suspicious when the matcher fires.
(field
  name: (identifier) @_field
  value: (string (string_content) @build-string)
  (#eq? @_field "build"))

;; ---- raw IP literal ---------------------------------------------------

;; Any string content containing http(s)://NNN.NNN.NNN.NNN
((string_content) @cap.raw-ip-literal
  (#match? @cap.raw-ip-literal "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"))
