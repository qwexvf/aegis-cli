; Tree-sitter queries for PHP dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes:
; - PHP function calls split into:
;   - bare:           (function_call_expression function: (name))
;   - scope-resolved: (scoped_call_expression scope: (name) name: (name))
;   - member call:    (member_call_expression object: ... name: (name))
; - Capability names match the suffix of domain.Capability.String().

;; ---- shell spawn -------------------------------------------------------

;; exec / shell_exec / system / passthru / popen / proc_open /
;; pcntl_exec — PHP's wide menagerie of shell-out functions.
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|escapeshellcmd|escapeshellarg)$"))
  @cap.shell-spawn

;; Backtick command: `cmd` — PHP parses this as a shell_command_expression
(shell_command_expression) @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

;; eval(...) / assert(<string>) — both execute strings as code in PHP
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(eval|assert|create_function)$"))
  @cap.dynamic-eval

;; preg_replace with /e modifier (eval'd replacement, deprecated PHP 7+
;; but still in legacy code). We can't easily detect /e from a regex
;; literal in tree-sitter, so we conservatively flag any preg_replace
;; whose pattern arg looks like it ends with /e or //e — see below.
;; This is best-effort; full detection requires runtime data.

;; Closure::fromCallable / call_user_func with dynamic arg — both
;; reachable RCE primitives in deserialization gadgets.
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(call_user_func|call_user_func_array)$"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; base64_decode / gzinflate / gzuncompress / str_rot13 — the canonical
;; encoded-payload chain in PHP webshells (often nested:
;; eval(gzinflate(base64_decode($payload)))).
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; HTTP-shaped fetches via stdlib: file_get_contents, fopen, readfile
;; with a URL arg. Capture the literal first arg and constrain to
;; http(s):// schemes. Both single-quoted (`string`) and double-quoted
;; (`encapsed_string`) forms.
(function_call_expression
  function: (name) @fn
  arguments: (arguments
    (argument [(string (string_content) @url)
               (encapsed_string (string_content) @url)]))
  (#match? @fn "^(file_get_contents|fopen|readfile|file)$")
  (#match? @url "^https?://"))
  @cap.net-egress

;; cURL family — any curl_init / curl_exec / curl_setopt is an egress
;; signal. Naming the sequence is overkill; flag the family entry
;; points conservatively.
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(curl_init|curl_exec|curl_multi_exec)$"))
  @cap.net-egress

;; Raw socket: fsockopen / socket_create / socket_connect /
;; stream_socket_client / stream_socket_server.
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(fsockopen|pfsockopen|socket_create|socket_connect|stream_socket_client|stream_socket_server)$"))
  @cap.net-egress

;; Guzzle / Symfony HttpClient method calls — `$client->get(...)`,
;; `Client::post(...)`. We match common verb names; over-fires on
;; benign `$obj->get($key)` but that's the price of not having type
;; resolution.
(member_call_expression
  name: (name) @method
  (#match? @method "^(get|post|put|delete|patch|head|request|sendAsync|send)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; getenv("NAME") with literal arg
(function_call_expression
  function: (name) @fn
  arguments: (arguments
    (argument [(string (string_content) @env_var)
               (encapsed_string (string_content) @env_var)]))
  (#eq? @fn "getenv"))

;; $_ENV['NAME'] / $_SERVER['NAME'] subscript access. The variable_name
;; node text includes the leading `$`; we match against `$_ENV` /
;; `$_SERVER` literally.
(subscript_expression
  (variable_name) @super
  [(string (string_content) @env_var)
   (encapsed_string (string_content) @env_var)]
  (#match? @super "^\\$(_ENV|_SERVER)$"))

;; ---- fs write outside root --------------------------------------------

;; file_put_contents / fwrite / file_put_contents-like family.
(function_call_expression
  function: (name) @fn
  (#match? @fn "^(file_put_contents|fwrite|fputs|fputcsv|copy|rename|symlink|link|move_uploaded_file|chmod|chown|chgrp|touch|mkdir)$"))
  @cap.fs-write-outside-root

;; fopen($, "w" / "a" / "wb" / etc.) — capture mode arg; lower
;; positives than name-only fopen since fopen is also used to read.
(function_call_expression
  function: (name) @fn
  arguments: (arguments
    (argument (_))
    (argument [(string (string_content) @mode)
               (encapsed_string (string_content) @mode)]))
  (#eq? @fn "fopen")
  (#match? @mode "^[wax][btr+]?$|^[btr+][wax]$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal

(encapsed_string (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
