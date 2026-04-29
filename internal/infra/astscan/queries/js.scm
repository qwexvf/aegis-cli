; Tree-sitter queries for JavaScript / TypeScript dangerous-pattern
; detection. Each capture name maps to a domain.Capability via
; capabilityFor() in jsscan/scanner.go.
;
; Notes on style:
; - Capture names are stable; renaming is a breaking change for the
;   scanner's switch dispatch.
; - Predicates (#eq?, #match?) restrict to patterns we care about.
; - Some patterns (env-read, raw-ip-literal) gather identifier or
;   string text we expose separately on Fingerprint.

;; ---- shell spawn -------------------------------------------------------
;; child_process.exec / execSync / spawn / spawnSync / fork / execFile
(call_expression
  function: (member_expression
    property: (property_identifier) @method
    (#match? @method "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$"))) @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------
;; eval(...)
(call_expression
  function: (identifier) @id
  (#eq? @id "eval")) @cap.dynamic-eval

;; new Function("..."), Function("...")
(new_expression
  constructor: (identifier) @id
  (#eq? @id "Function")) @cap.dynamic-eval

(call_expression
  function: (identifier) @id
  (#eq? @id "Function")) @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------
;; atob("...")
(call_expression
  function: (identifier) @id
  (#eq? @id "atob")) @cap.base64-decode

;; Buffer.from(x, 'base64')
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

;; ---- env reads ---------------------------------------------------------
;; process.env.SOMETHING (member access)
(member_expression
  object: (member_expression
    object: (identifier) @p
    property: (property_identifier) @e)
  property: (property_identifier) @env_var
  (#eq? @p "process")
  (#eq? @e "env")) @cap.env-read

;; process.env["SOMETHING"] (subscript access)
(subscript_expression
  object: (member_expression
    object: (identifier) @p
    property: (property_identifier) @e)
  index: (string (string_fragment) @env_var)
  (#eq? @p "process")
  (#eq? @e "env")) @cap.env-read

;; ---- fs writes outside root -------------------------------------------
;; fs.writeFile / writeFileSync / appendFile / appendFileSync /
;; createWriteStream
(call_expression
  function: (member_expression
    object: (identifier) @fs
    property: (property_identifier) @method)
  (#match? @fs "^(fs|fsPromises)$")
  (#match? @method "^(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ---------------------------------------------------
;; "https://1.2.3.4..." or "http://1.2.3.4..."
(string (string_fragment) @ip
  (#match? @ip "^https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) @cap.raw-ip-literal
