; Tree-sitter queries for JavaScript / TypeScript dangerous-pattern
; detection. Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes:
; - We can't easily track destructuring across nodes in pure
;   tree-sitter queries (no inter-node bindings). So we match BOTH:
;     a) direct member calls: `cp.exec(...)`
;     b) require('module') anywhere — implies the module is "in scope"
;   This over-triggers a bit (false positives on db.exec etc.) but is
;   the conservative choice for a security tool — a missed signal is
;   silent. The user can override with audit.

;; ---- shell spawn -------------------------------------------------------

;; require('child_process')
(call_expression
  function: (identifier) @fn
  (#eq? @fn "require")
  arguments: (arguments
    (string (string_fragment) @mod
      (#eq? @mod "child_process")))) @cap.shell-spawn

;; obj.exec/execSync/spawn/spawnSync/fork/execFile(/Sync)
(call_expression
  function: (member_expression
    property: (property_identifier) @method
    (#match? @method "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$")))
  @cap.shell-spawn

;; bare execSync/spawnSync/execFileSync — high-confidence destructured
;; call. We deliberately exclude bare "exec"/"spawn" because too many
;; libs use them benignly.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(execSync|execFileSync|spawnSync)$")) @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

(call_expression
  function: (identifier) @id
  (#eq? @id "eval")) @cap.dynamic-eval

(new_expression
  constructor: (identifier) @id
  (#eq? @id "Function")) @cap.dynamic-eval

(call_expression
  function: (identifier) @id
  (#eq? @id "Function")) @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

(call_expression
  function: (identifier) @id
  (#eq? @id "atob")) @cap.base64-decode

(call_expression
  function: (member_expression
    object: (identifier) @o
    property: (property_identifier) @p
    (#eq? @o "Buffer")
    (#eq? @p "from"))
  arguments: (arguments
    (_)
    (string (string_fragment) @enc
      (#eq? @enc "base64")))) @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; require('http' | 'https' | 'net' | 'dgram' | 'tls')
(call_expression
  function: (identifier) @fn
  (#eq? @fn "require")
  arguments: (arguments
    (string (string_fragment) @mod
      (#match? @mod "^(http|https|net|dgram|tls)$")))) @cap.net-egress

;; fetch(...)
(call_expression
  function: (identifier) @id
  (#eq? @id "fetch")) @cap.net-egress

;; new XMLHttpRequest()
(new_expression
  constructor: (identifier) @id
  (#eq? @id "XMLHttpRequest")) @cap.net-egress

;; ---- env reads ---------------------------------------------------------

;; process.env.SOMETHING
(member_expression
  object: (member_expression
    object: (identifier) @p
    property: (property_identifier) @e)
  property: (property_identifier) @env_var
  (#eq? @p "process")
  (#eq? @e "env")) @cap.env-read

;; process.env["SOMETHING"]
(subscript_expression
  object: (member_expression
    object: (identifier) @p
    property: (property_identifier) @e)
  index: (string (string_fragment) @env_var)
  (#eq? @p "process")
  (#eq? @e "env")) @cap.env-read

;; ---- fs writes outside root -------------------------------------------

;; require('fs') / require('fs/promises')
(call_expression
  function: (identifier) @fn
  (#eq? @fn "require")
  arguments: (arguments
    (string (string_fragment) @mod
      (#match? @mod "^(fs|fs/promises|graceful-fs)$")))) @cap.fs-write-outside-root

;; obj.writeFile/writeFileSync/appendFile/appendFileSync/createWriteStream
(call_expression
  function: (member_expression
    property: (property_identifier) @method
    (#match? @method "^(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)$")))
  @cap.fs-write-outside-root

;; bare writeFileSync / appendFileSync (destructured)
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(writeFileSync|appendFileSync)$")) @cap.fs-write-outside-root

;; ---- raw IP literal ---------------------------------------------------

(string (string_fragment) @ip
  (#match? @ip "^https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) @cap.raw-ip-literal
