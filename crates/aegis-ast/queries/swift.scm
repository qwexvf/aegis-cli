; Tree-sitter queries for Swift dangerous-pattern detection.
; Bare calls are (call_expression (simple_identifier) (call_suffix ...)).
; Member calls are (call_expression (navigation_expression suffix:
;   (navigation_suffix suffix: (simple_identifier))) (call_suffix ...)).
; Capability names match Capability::name().

;; ---- shell spawn -------------------------------------------------------

;; system("...") / popen / execv*  (C interop, common in Swift malware)
(call_expression
  (simple_identifier) @fn
  (#match? @fn "^(system|popen|execv|execvp|execl|posix_spawn)$"))
  @cap.shell-spawn

;; Process() construction
(call_expression
  (simple_identifier) @fn
  (#eq? @fn "Process"))
  @cap.shell-spawn

;; process.launch() / process.run()
(call_expression
  (navigation_expression
    suffix: (navigation_suffix suffix: (simple_identifier) @method))
  (#match? @method "^(launch|run)$"))
  @cap.shell-spawn

;; ---- base64 decode -----------------------------------------------------

;; Data(base64Encoded: ...) — argument label carries the intent.
(call_expression
  (simple_identifier) @fn
  (call_suffix
    (value_arguments
      (value_argument name: (value_argument_label (simple_identifier) @label))))
  (#eq? @fn "Data")
  (#eq? @label "base64Encoded"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; URLSession...dataTask / downloadTask / uploadTask
(call_expression
  (navigation_expression
    suffix: (navigation_suffix suffix: (simple_identifier) @method))
  (#match? @method "^(dataTask|downloadTask|uploadTask)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; ProcessInfo.processInfo.environment["NAME"] — subscript parses as a
;; call_suffix carrying the key string literal.
(call_expression
  (navigation_expression
    suffix: (navigation_suffix suffix: (simple_identifier) @method))
  (call_suffix
    (value_arguments
      (value_argument value: (line_string_literal text: (line_str_text) @env_var))))
  (#eq? @method "environment"))

;; getenv("NAME")
(call_expression
  (simple_identifier) @fn
  (call_suffix
    (value_arguments
      (value_argument value: (line_string_literal text: (line_str_text) @env_var))))
  (#eq? @fn "getenv"))

;; ---- fs write outside root --------------------------------------------

;; "...".write(toFile:...) / data.write(to:) / FileManager.createFile
(call_expression
  (navigation_expression
    suffix: (navigation_suffix suffix: (simple_identifier) @method))
  (#match? @method "^(write|writeToFile|createFile)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(line_string_literal text: (line_str_text) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
