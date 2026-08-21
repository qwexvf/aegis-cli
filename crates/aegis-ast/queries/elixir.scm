; Tree-sitter queries for Elixir dangerous-pattern detection.
; Qualified calls are (call target: (dot left: (alias|atom) right: (identifier))).
; Capability names match Capability::name().

;; ---- shell spawn -------------------------------------------------------

;; System.cmd / System.shell
(call
  target: (dot
    left: (alias) @mod
    right: (identifier) @fn)
  (#eq? @mod "System")
  (#match? @fn "^(cmd|shell)$"))
  @cap.shell-spawn

;; :os.cmd(...) / :erlang.open_port(...)
(call
  target: (dot
    left: (atom) @mod
    right: (identifier) @fn)
  (#match? @mod "^:(os|erlang)$")
  (#match? @fn "^(cmd|open_port)$"))
  @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

(call
  target: (dot
    left: (alias) @mod
    right: (identifier) @fn)
  (#eq? @mod "Code")
  (#match? @fn "^(eval_string|eval_quoted|eval_file|compile_string|compile_quoted|require_file)$"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

(call
  target: (dot
    left: (alias) @mod
    right: (identifier) @fn)
  (#eq? @mod "Base")
  (#match? @fn "^(decode64|decode64!|url_decode64|url_decode64!|decode32|decode32!|decode16|decode16!|hex_decode64)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; HTTPoison / Req / Finch / Tesla / HTTPotion
(call
  target: (dot
    left: (alias) @mod
    right: (identifier) @fn)
  (#match? @mod "^(HTTPoison|Req|Finch|Tesla|HTTPotion|Mint)$")
  (#match? @fn "^(get|get!|post|post!|put|put!|patch|delete|request|head)$"))
  @cap.net-egress

;; :httpc.request / :gen_tcp.connect / :ssl.connect
(call
  target: (dot
    left: (atom) @mod
    right: (identifier) @fn)
  (#match? @mod "^:(httpc|gen_tcp|ssl|inets)$")
  (#match? @fn "^(request|connect|open)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; System.get_env("NAME") / System.fetch_env!("NAME")
(call
  target: (dot
    left: (alias) @mod
    right: (identifier) @fn)
  (arguments
    (string (quoted_content) @env_var))
  (#eq? @mod "System")
  (#match? @fn "^(get_env|fetch_env|fetch_env!)$"))

;; ---- fs write outside root --------------------------------------------

(call
  target: (dot
    left: (alias) @mod
    right: (identifier) @fn)
  (#eq? @mod "File")
  (#match? @fn "^(write|write!|open|open!|cp|cp!|cp_r|cp_r!|rename|rename!|copy|copy!|touch|touch!|mkdir|mkdir!|mkdir_p|mkdir_p!|rm|rm!)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string (quoted_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
