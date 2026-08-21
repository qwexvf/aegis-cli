; Tree-sitter queries for Kotlin dangerous-pattern detection (grammar:
; tree-sitter-kotlin-ng). Member calls are
; (call_expression (navigation_expression (_) (identifier))). The method
; name is the last identifier child of the navigation_expression.
; Capability names match Capability::name().

;; ---- shell spawn -------------------------------------------------------

;; Runtime.getRuntime().exec(...)  /  anything .exec(...)
(call_expression
  (navigation_expression (identifier) @method .)
  (#eq? @method "exec"))
  @cap.shell-spawn

;; ProcessBuilder("...") construction
(call_expression
  (identifier) @fn
  (#eq? @fn "ProcessBuilder"))
  @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

;; scriptEngine.eval(...) / KotlinScript eval
(call_expression
  (navigation_expression (identifier) @method .)
  (#eq? @method "eval"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; Base64.getDecoder().decode(...) — flag the .decode call.
(call_expression
  (navigation_expression (identifier) @method .)
  (#match? @method "^(decode|decodeToString)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; URL(...).openConnection() / .openStream() / OkHttp .newCall(...)
(call_expression
  (navigation_expression (identifier) @method .)
  (#match? @method "^(openConnection|openStream|newCall)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; System.getenv("NAME")
(call_expression
  (navigation_expression (identifier) @obj (identifier) @method .)
  (value_arguments
    (value_argument (string_literal (string_content) @env_var)))
  (#eq? @obj "System")
  (#eq? @method "getenv"))

;; ---- fs write outside root --------------------------------------------

;; File(...).writeText / writeBytes / appendText / appendBytes
(call_expression
  (navigation_expression (identifier) @method .)
  (#match? @method "^(writeText|writeBytes|appendText|appendBytes|printWriter|bufferedWriter)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string_literal (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
