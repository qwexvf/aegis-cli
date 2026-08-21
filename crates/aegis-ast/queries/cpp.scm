; Tree-sitter queries for C++ dangerous-pattern detection.
; Superset of the C query: same bare-identifier calls, plus a
; qualified-identifier arm for `std::system`, `std::getenv`, etc.
; Capability names match Capability::name().

;; ---- shell spawn -------------------------------------------------------

(call_expression
  function: (identifier) @fn
  (#match? @fn "^(system|popen|execl|execlp|execle|execv|execvp|execvpe|execve|fork|vfork|posix_spawn|posix_spawnp)$"))
  @cap.shell-spawn

;; std::system / std::popen
(call_expression
  function: (qualified_identifier
    name: (identifier) @fn)
  (#match? @fn "^(system|popen)$"))
  @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

(call_expression
  function: (identifier) @fn
  (#match? @fn "^(dlopen|dlsym|LoadLibrary|LoadLibraryA|LoadLibraryW|GetProcAddress)$"))
  @cap.dynamic-eval

;; ---- net egress --------------------------------------------------------

(call_expression
  function: (identifier) @fn
  (#match? @fn "^(socket|connect|gethostbyname|getaddrinfo|curl_easy_perform|curl_easy_init)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    (string_literal (string_content) @env_var))
  (#match? @fn "^(getenv|secure_getenv)$"))

;; std::getenv("NAME")
(call_expression
  function: (qualified_identifier
    name: (identifier) @fn)
  arguments: (argument_list
    (string_literal (string_content) @env_var))
  (#eq? @fn "getenv"))

;; ---- fs write outside root --------------------------------------------

(call_expression
  function: (identifier) @fn
  (#match? @fn "^(fopen|open|open64|creat|fwrite|rename|remove|unlink|mkdir)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string_literal (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
