; Tree-sitter queries for C dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain Capability via capability_for()
; in scanner.rs. Capability names match Capability::name().
;
; C calls are (call_expression function: (identifier) arguments: ...).
; String literals are (string_literal (string_content)).

;; ---- shell spawn -------------------------------------------------------

;; system / popen / exec* family / fork / posix_spawn
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(system|popen|execl|execlp|execle|execv|execvp|execvpe|execve|fork|vfork|posix_spawn|posix_spawnp)$"))
  @cap.shell-spawn

;; ---- dynamic eval (runtime code loading) -------------------------------

;; dlopen / dlsym — runtime-determined shared-object load, the C analogue
;; of eval/exec.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(dlopen|dlsym)$"))
  @cap.dynamic-eval

;; ---- net egress --------------------------------------------------------

(call_expression
  function: (identifier) @fn
  (#match? @fn "^(socket|connect|gethostbyname|getaddrinfo|curl_easy_perform|curl_easy_init)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; getenv("NAME") / secure_getenv("NAME") — capture the literal key.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    (string_literal (string_content) @env_var))
  (#match? @fn "^(getenv|secure_getenv)$"))

;; ---- fs write outside root --------------------------------------------

(call_expression
  function: (identifier) @fn
  (#match? @fn "^(fopen|open|open64|creat|fwrite|rename|remove|unlink|mkdir)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string_literal (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
