; Tree-sitter queries for Ruby dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design mirrors pyscan/queries.scm:
; - Direct method calls on a known module (e.g. Net::HTTP.get) and
;   bare-identifier calls (e.g. system "...") are matched independently.
; - Ruby-specific shapes: backtick command (`\`cmd\``), %x{cmd} string,
;   %w arrays, scope_resolution for Net::HTTP / Open3.
; - Capability names match the suffix of domain.Capability.String().

;; ---- shell spawn -------------------------------------------------------

;; bare system / exec / spawn / fork
(call
  method: (identifier) @fn
  (#match? @fn "^(system|exec|spawn|fork)$"))
  @cap.shell-spawn

;; Kernel.system / Kernel.exec / Process.spawn / Process.exec
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(Kernel|Process)$")
  (#match? @method "^(system|exec|spawn)$"))
  @cap.shell-spawn

;; IO.popen / IO.read("|cmd") (read with leading pipe is shell)
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "IO")
  (#match? @method "^(popen|popen2|popen3|popen2e)$"))
  @cap.shell-spawn

;; Open3.{popen2,popen3,capture2,capture3,pipeline,...}
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "Open3")
  (#match? @method "^(popen2|popen3|popen2e|capture2|capture3|capture2e|pipeline|pipeline_r|pipeline_w|pipeline_rw|pipeline_start)$"))
  @cap.shell-spawn

;; PTY.{spawn,getpty} — interactive shell drop
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "PTY")
  (#match? @method "^(spawn|getpty)$"))
  @cap.shell-spawn

;; Backticks `cmd` and %x{cmd} both parse as the same node in
;; tree-sitter-ruby — the executable-string form.
(subshell) @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

;; bare eval / instance_eval / class_eval / module_eval
(call
  method: (identifier) @fn
  (#match? @fn "^(eval|instance_eval|class_eval|module_eval|binding_eval)$"))
  @cap.dynamic-eval

;; Kernel.eval / Module.module_eval (qualified)
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(Kernel|Module|Object|BasicObject)$")
  (#match? @method "^(eval|instance_eval|class_eval|module_eval)$"))
  @cap.dynamic-eval

;; send / public_send / __send__ with literal symbol — meta-programming
;; that often shows up paired with eval in malware. Conservative: only
;; flag when the call has no receiver (likely a method invocation, not
;; ActionMailer-style chaining).
(call
  method: (identifier) @fn
  (#match? @fn "^(send|public_send|__send__)$"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; Base64.{decode64,urlsafe_decode64,strict_decode64}
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "Base64")
  (#match? @method "^(decode64|urlsafe_decode64|strict_decode64)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; Net::HTTP.{get,post,start,...} via scope_resolution receiver
(call
  receiver: (scope_resolution
    scope: (constant) @top
    name: (constant) @sub)
  method: (identifier) @method
  (#eq? @top "Net")
  (#eq? @sub "HTTP")
  (#match? @method "^(get|post|put|delete|patch|head|start|get_response|get_print|new)$"))
  @cap.net-egress

;; Net::HTTPS.start — same shape
(call
  receiver: (scope_resolution
    scope: (constant) @top
    name: (constant) @sub)
  method: (identifier) @method
  (#eq? @top "Net")
  (#eq? @sub "HTTPS"))
  @cap.net-egress

;; URI.{open,parse,read} — open-uri and friends
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "URI")
  (#match? @method "^(open|read|parse)$"))
  @cap.net-egress

;; bare open() with a URL-shaped string — open-uri-mixed-in
;; (Conservative: only fires when the first arg starts with http(s)://)
(call
  method: (identifier) @fn
  arguments: (argument_list
    (string (string_content) @arg))
  (#eq? @fn "open")
  (#match? @arg "^https?://"))
  @cap.net-egress

;; HTTParty / RestClient / Faraday / Excon (popular HTTP gems)
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(HTTParty|RestClient|Faraday|Excon|Typhoeus)$")
  (#match? @method "^(get|post|put|delete|patch|head|new|request)$"))
  @cap.net-egress

;; TCPSocket.new / Socket.new / UDPSocket.new — raw socket egress
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(TCPSocket|UDPSocket|Socket|UNIXSocket)$")
  (#match? @method "^(new|open)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; ENV['NAME']
(element_reference
  object: (constant) @mod
  (string (string_content) @env_var)
  (#eq? @mod "ENV"))

;; ENV.fetch('NAME', ...) / ENV['NAME']= (the latter is a write but
;; tree-sitter element_assignment is a different node so it won't
;; collide)
(call
  receiver: (constant) @mod
  method: (identifier) @method
  arguments: (argument_list
    (string (string_content) @env_var))
  (#eq? @mod "ENV")
  (#match? @method "^(fetch|\\[\\])$"))

;; ---- fs write outside root --------------------------------------------

;; File.open('path', 'w') / 'a' — capture mode arg
(call
  receiver: (constant) @mod
  method: (identifier) @method
  arguments: (argument_list
    (_)
    (string (string_content) @mode))
  (#eq? @mod "File")
  (#eq? @method "open")
  (#match? @mode "^[wax][btr+]?$|^[btr+][wax]$"))
  @cap.fs-write-outside-root

;; File.write / File.write_binary / IO.write
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(File|IO)$")
  (#match? @method "^(write|binwrite|append)$"))
  @cap.fs-write-outside-root

;; FileUtils.{cp,mv,install,cp_r,mv_r,copy_file}
(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "FileUtils")
  (#match? @method "^(cp|mv|cp_r|mv_r|copy|copy_file|copy_entry|install)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------
;; http(s)://NNN.NNN.NNN.NNN inside a string literal.

(string (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
