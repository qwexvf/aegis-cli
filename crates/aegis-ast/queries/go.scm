; Tree-sitter queries for Go dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes:
; - Go calls split into two AST shapes:
;   - bare:       (call_expression function: (identifier))
;   - qualified:  (call_expression function: (selector_expression
;                                              operand: (identifier) @pkg
;                                              field: (field_identifier) @name))
;   Most malware uses the qualified form (`exec.Command`, `os.Getenv`,
;   `http.Get`) so we lean on that. Bare-name shapes (after `import .`
;   or local re-bind) are ignored — vanishingly rare in real code.
; - Capability names match the suffix of domain.Capability.String().

;; ---- shell spawn -------------------------------------------------------

;; os/exec — Command / CommandContext
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "exec")
  (#match? @name "^(Command|CommandContext|LookPath)$"))
  @cap.shell-spawn

;; syscall — Exec / ForkExec / StartProcess (low-level fork/exec)
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "syscall")
  (#match? @name "^(Exec|ForkExec|StartProcess)$"))
  @cap.shell-spawn

;; os.StartProcess — same low-level surface, different package
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "os")
  (#eq? @name "StartProcess"))
  @cap.shell-spawn

;; ---- dynamic eval (Go analogue: plugin loading) ------------------------

;; plugin.Open — Go's runtime-determined .so loader, the closest
;; equivalent to eval/exec in safe Go code.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "plugin")
  (#eq? @name "Open"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; base64.{StdEncoding,RawStdEncoding,URLEncoding,RawURLEncoding}.{DecodeString,Decode}
;; Two-level field access: pkg.Encoding.Method. Match the leaf field
;; only and constrain the package name.
(call_expression
  function: (selector_expression
    operand: (selector_expression
      operand: (identifier) @pkg)
    field: (field_identifier) @name)
  (#eq? @pkg "base64")
  (#match? @name "^(DecodeString|Decode|DecodedLen)$"))
  @cap.base64-decode

;; hex / encoding/hex similar — flag the package name when it's hex
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "hex")
  (#match? @name "^(DecodeString|Decode)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; net/http — Get / Post / PostForm / Head
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "http")
  (#match? @name "^(Get|Post|PostForm|Head|NewRequest|NewRequestWithContext)$"))
  @cap.net-egress

;; net — Dial / DialTimeout / DialContext / Listen
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "net")
  (#match? @name "^(Dial|DialTimeout|DialContext|Listen|ListenPacket)$"))
  @cap.net-egress

;; tls.Dial — same as net.Dial but with TLS
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "tls")
  (#match? @name "^(Dial|DialWithDialer)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; os.Getenv("NAME") / os.LookupEnv("NAME"). Capture the literal arg
;; for the credential-shaped-name filter applied at scoring time.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  arguments: (argument_list
    (interpreted_string_literal (interpreted_string_literal_content) @env_var))
  (#eq? @pkg "os")
  (#match? @name "^(Getenv|LookupEnv)$"))

;; ---- fs write outside root --------------------------------------------

;; os.WriteFile / os.Create / os.OpenFile (modes containing O_WRONLY/RDWR
;; are flag-laden in Go — over-tagging slightly is acceptable here)
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "os")
  (#match? @name "^(WriteFile|Create|OpenFile|Mkdir|MkdirAll|Rename|Symlink|Link)$"))
  @cap.fs-write-outside-root

;; ioutil.WriteFile — pre-1.16, still everywhere in real-world code
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @name)
  (#eq? @pkg "ioutil")
  (#eq? @name "WriteFile"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------
;; Go uses interpreted_string_literal_content for the inner text of "..."
;; and raw_string_literal_content for `...`.

(interpreted_string_literal (interpreted_string_literal_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal

(raw_string_literal (raw_string_literal_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
