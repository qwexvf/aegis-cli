; Tree-sitter queries for Python dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes mirror the JS scanner:
; - Direct attribute calls (`subprocess.run(...)`) and require/import
;   patterns are matched independently — destructuring imports
;   (`from subprocess import run`) escape pure tree-sitter so we
;   compromise on slight over-triggering rather than false negatives.
; - Capability names match the suffix of domain.Capability.String()
;   so capabilityFor() can map by string.

;; ---- shell spawn -------------------------------------------------------

;; subprocess.{run,call,Popen,check_call,check_output,getoutput,getstatusoutput}
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#eq? @mod "subprocess")
  (#match? @method "^(run|call|Popen|check_call|check_output|getoutput|getstatusoutput)$"))
  @cap.shell-spawn

;; os.{system,popen,spawn*,exec*}
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#eq? @mod "os")
  (#match? @method "^(system|popen|spawn[lvep]+|exec[lvep]+)$"))
  @cap.shell-spawn

;; commands.getoutput / commands.getstatusoutput (deprecated but seen in malware)
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#eq? @mod "commands")
  (#match? @method "^(getoutput|getstatusoutput)$"))
  @cap.shell-spawn

;; pty.spawn — interactive shell drop
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#eq? @mod "pty")
  (#eq? @method "spawn"))
  @cap.shell-spawn

;; bare run/Popen/check_output — destructured-import shape, slightly
;; over-triggers (any `run(...)` call) but high-signal in malware.
;; Note: many libs use bare `run` benignly (testing libs, click, etc.) —
;; intentionally NOT included. Only the unambiguous Popen.
(call
  function: (identifier) @fn
  (#match? @fn "^(Popen|check_output|check_call)$"))
  @cap.shell-spawn

;; ---- dynamic eval ------------------------------------------------------

(call
  function: (identifier) @fn
  (#match? @fn "^(eval|exec|compile)$"))
  @cap.dynamic-eval

;; __import__('foo') — used for runtime-determined imports of
;; dangerous modules. Often paired with eval/exec.
(call
  function: (identifier) @fn
  (#eq? @fn "__import__"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#match? @mod "^(base64|codecs|binascii)$")
  (#match? @method "^(b64decode|standard_b64decode|urlsafe_b64decode|decode|a2b_base64|a2b_hex|unhexlify)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; urllib / urllib2 / urllib.request / requests / httpx / aiohttp
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#match? @mod "^(urllib|urllib2|requests|httpx|aiohttp)$")
  (#match? @method "^(urlopen|get|post|put|delete|patch|request|head|options)$"))
  @cap.net-egress

;; urllib.request.urlopen (longer chain)
(call
  function: (attribute
    object: (attribute
      object: (identifier) @top
      attribute: (identifier) @sub)
    attribute: (identifier) @leaf)
  (#eq? @top "urllib")
  (#eq? @sub "request")
  (#match? @leaf "^(urlopen|Request|build_opener|install_opener)$"))
  @cap.net-egress

;; socket.{socket,create_connection,connection,...} — raw socket egress
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#eq? @mod "socket")
  (#match? @method "^(socket|create_connection|create_server)$"))
  @cap.net-egress

;; http.client.HTTPConnection — stdlib HTTP
(call
  function: (attribute
    object: (attribute
      object: (identifier) @top
      attribute: (identifier) @sub)
    attribute: (identifier) @leaf)
  (#eq? @top "http")
  (#eq? @sub "client")
  (#match? @leaf "^(HTTPConnection|HTTPSConnection)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; os.environ['NAME'] — capture the literal key as @env_var so the
;; scanner can apply the credential-shaped-name filter.
(subscript
  value: (attribute
    object: (identifier) @mod
    attribute: (identifier) @attr)
  subscript: (string (string_content) @env_var)
  (#eq? @mod "os")
  (#eq? @attr "environ"))

;; os.environ.get('NAME')
(call
  function: (attribute
    object: (attribute
      object: (identifier) @mod
      attribute: (identifier) @attr)
    attribute: (identifier) @method)
  arguments: (argument_list
    (string (string_content) @env_var))
  (#eq? @mod "os")
  (#eq? @attr "environ")
  (#eq? @method "get"))

;; os.getenv('NAME')
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  arguments: (argument_list
    (string (string_content) @env_var))
  (#eq? @mod "os")
  (#eq? @method "getenv"))

;; ---- fs write outside root --------------------------------------------

;; open(..., 'w' | 'a' | 'wb' | 'ab' | ...)
(call
  function: (identifier) @fn
  arguments: (argument_list
    (_)
    (string (string_content) @mode))
  (#eq? @fn "open")
  (#match? @mode "^[wax][btr+]?$|^[btr+][wax]$"))
  @cap.fs-write-outside-root

;; pathlib.Path(...).write_text / write_bytes
(call
  function: (attribute
    attribute: (identifier) @method)
  (#match? @method "^(write_text|write_bytes)$"))
  @cap.fs-write-outside-root

;; shutil.copy* / shutil.move
(call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @method)
  (#eq? @mod "shutil")
  (#match? @method "^(copy|copy2|copyfile|copyfileobj|copytree|move)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------
;; Conservative: match any string literal that LOOKS like an IPv4
;; preceded by http(s):// — same convention as the JS scanner.

(string (string_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
