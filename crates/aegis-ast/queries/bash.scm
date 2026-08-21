; Tree-sitter queries for Bash dangerous-pattern detection.
; Commands are (command name: (command_name (word))). Capability names
; match Capability::name().

;; ---- shell spawn -------------------------------------------------------

;; explicit interpreter / exec / source of another script
(command
  name: (command_name (word) @cmd)
  (#match? @cmd "^(sh|bash|zsh|dash|ash|ksh|exec|source)$"))
  @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

(command
  name: (command_name (word) @cmd)
  (#eq? @cmd "eval"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

(command
  name: (command_name (word) @cmd)
  (#match? @cmd "^(base64|base32|xxd|uudecode)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

(command
  name: (command_name (word) @cmd)
  (#match? @cmd "^(curl|wget|nc|ncat|netcat|telnet|scp|sftp|ftp|ssh)$"))
  @cap.net-egress

;; ---- raw IP literal ----------------------------------------------------
;; bare words and quoted strings that look like http://<ipv4>

((word) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal

(string (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
