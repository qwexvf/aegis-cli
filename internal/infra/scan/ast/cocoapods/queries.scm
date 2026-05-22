; Tree-sitter queries for CocoaPods .podspec dangerous-pattern detection.
; Podspecs are Ruby DSL evaluated at `pod install`. The base Ruby
; capability set (mirrors ruby/queries.scm) applies, plus podspec-
; specific surfaces (prepare_command, script_phase, source_files set
; to shell-evaluated globs).
;
; Each "@cap.X" capture maps to a domain.Capability via capabilityFor().

;; ---- podspec install-time surfaces -------------------------------------

;; s.prepare_command = "shell ..." — runs at pod install time, always.
;; Tree-sitter shape: assignment where left is `s.prepare_command`-like.
(assignment
  left: (call
    method: (identifier) @attr)
  right: (string)
  (#eq? @attr "prepare_command"))
  @cap.shell-spawn

;; s.script_phase :name => "X", :script => "...shell..."
;; Triggers at every consumer build. Whole call flagged as shell-spawn.
(call
  method: (identifier) @fn
  (#eq? @fn "script_phase"))
  @cap.shell-spawn

;; ---- shell spawn -------------------------------------------------------

(call
  method: (identifier) @fn
  (#match? @fn "^(system|exec|spawn|fork)$"))
  @cap.shell-spawn

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(Kernel|Process)$")
  (#match? @method "^(system|exec|spawn)$"))
  @cap.shell-spawn

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "IO")
  (#match? @method "^(popen|popen2|popen3|popen2e)$"))
  @cap.shell-spawn

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "Open3")
  (#match? @method "^(popen2|popen3|popen2e|capture2|capture3|capture2e|pipeline|pipeline_r|pipeline_w|pipeline_rw|pipeline_start)$"))
  @cap.shell-spawn

(subshell) @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

(call
  method: (identifier) @fn
  (#match? @fn "^(eval|instance_eval|class_eval|module_eval|binding_eval)$"))
  @cap.dynamic-eval

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(Kernel|Module|Object|BasicObject)$")
  (#match? @method "^(eval|instance_eval|class_eval|module_eval)$"))
  @cap.dynamic-eval

(call
  method: (identifier) @fn
  (#match? @fn "^(send|public_send|__send__)$"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "Base64")
  (#match? @method "^(decode64|urlsafe_decode64|strict_decode64)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

(call
  receiver: (scope_resolution
    scope: (constant) @top
    name: (constant) @sub)
  method: (identifier) @method
  (#eq? @top "Net")
  (#eq? @sub "HTTP")
  (#match? @method "^(get|post|put|delete|patch|head|start|get_response|get_print|new)$"))
  @cap.net-egress

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "URI")
  (#match? @method "^(open|read|parse)$"))
  @cap.net-egress

(call
  method: (identifier) @fn
  arguments: (argument_list
    (string (string_content) @arg))
  (#eq? @fn "open")
  (#match? @arg "^https?://"))
  @cap.net-egress

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(TCPSocket|UDPSocket|Socket|UNIXSocket)$")
  (#match? @method "^(new|open)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

(element_reference
  object: (constant) @mod
  (string (string_content) @env_var)
  (#eq? @mod "ENV"))

(call
  receiver: (constant) @mod
  method: (identifier) @method
  arguments: (argument_list
    (string (string_content) @env_var))
  (#eq? @mod "ENV")
  (#match? @method "^(fetch|\\[\\])$"))

;; ---- fs write outside root --------------------------------------------

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

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#match? @mod "^(File|IO)$")
  (#match? @method "^(write|binwrite|append)$"))
  @cap.fs-write-outside-root

(call
  receiver: (constant) @mod
  method: (identifier) @method
  (#eq? @mod "FileUtils")
  (#match? @method "^(cp|mv|cp_r|mv_r|copy|copy_file|copy_entry|install)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
