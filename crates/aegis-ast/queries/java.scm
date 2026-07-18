; Tree-sitter queries for Java dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes:
; - Java method calls split into:
;   - bare:        (method_invocation name: (identifier))
;   - qualified:   (method_invocation
;                     object: (identifier|field_access)
;                     name: (identifier))
;   Most malware uses qualified form (Runtime.getRuntime().exec(...),
;   ProcessBuilder().start(), etc.). Bare-name shapes after `import static`
;   are caught by name-only matches where unambiguous.
; - Java's per-package import system means we capture both the leaf
;   identifier and (when feasible) the qualifying chain.

;; ---- shell spawn -------------------------------------------------------

;; Runtime.getRuntime().exec(...) — the canonical Java shell-out.
;; Match the .exec call on something whose chain looks like
;; "*.getRuntime().exec".
(method_invocation
  name: (identifier) @method
  (#eq? @method "exec"))
  @cap.shell-spawn

;; ProcessBuilder(...).start()
(method_invocation
  object: (object_creation_expression
    type: (type_identifier) @cls)
  name: (identifier) @method
  (#eq? @cls "ProcessBuilder")
  (#eq? @method "start"))
  @cap.shell-spawn

;; ProcessBuilder via variable reference: pb.start() where pb was
;; declared as ProcessBuilder. We can't trace the type without full
;; type resolution, so we lean on the unambiguous start() call after
;; an object_creation_expression above. Bare .start() is too noisy.

;; Runtime.getRuntime() — capture the runtime object handle being
;; obtained. exec/halt usage downstream is what fires shell-spawn,
;; but obtaining a runtime alone is also a yellow flag.
(method_invocation
  object: (identifier) @cls
  name: (identifier) @method
  (#eq? @cls "Runtime")
  (#eq? @method "getRuntime"))
  @cap.shell-spawn

;; ---- dynamic eval (Java analogue: reflection + class loading) ----------

;; Class.forName(...) — runtime-determined class load, the canonical
;; Java RCE entry-point ("ClassLoader gadgets").
(method_invocation
  object: (identifier) @cls
  name: (identifier) @method
  (#eq? @cls "Class")
  (#eq? @method "forName"))
  @cap.dynamic-eval

;; ClassLoader.loadClass / defineClass / getSystemClassLoader — same
;; family of runtime class loading.
(method_invocation
  name: (identifier) @method
  (#match? @method "^(loadClass|defineClass|getSystemClassLoader)$"))
  @cap.dynamic-eval

;; Method.invoke(...) — reflective invocation, the gadget chain finale.
(method_invocation
  name: (identifier) @method
  (#eq? @method "invoke"))
  @cap.dynamic-eval

;; ScriptEngine.eval(...) — Nashorn / Rhino / GraalJS in-process eval.
;; Caught by name match (eval is unambiguous in Java context).
(method_invocation
  name: (identifier) @method
  (#eq? @method "eval"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; Base64.getDecoder().decode(...) — Java 8+ canonical
(method_invocation
  object: (method_invocation
    object: (identifier) @cls
    name: (identifier) @decoder)
  name: (identifier) @method
  (#eq? @cls "Base64")
  (#eq? @decoder "getDecoder")
  (#eq? @method "decode"))
  @cap.base64-decode

;; Base64.getMimeDecoder() / getUrlDecoder() — variants
(method_invocation
  object: (method_invocation
    object: (identifier) @cls
    name: (identifier) @decoder)
  name: (identifier) @method
  (#eq? @cls "Base64")
  (#match? @decoder "^(getMimeDecoder|getUrlDecoder)$")
  (#eq? @method "decode"))
  @cap.base64-decode

;; DatatypeConverter.parseBase64Binary — pre-Java-8 standard
(method_invocation
  object: (identifier) @cls
  name: (identifier) @method
  (#eq? @cls "DatatypeConverter")
  (#eq? @method "parseBase64Binary"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; new URL(...).openConnection() / openStream()
(method_invocation
  object: (object_creation_expression
    type: (type_identifier) @cls)
  name: (identifier) @method
  (#eq? @cls "URL")
  (#match? @method "^(openConnection|openStream)$"))
  @cap.net-egress

;; Socket / ServerSocket / DatagramSocket constructor — raw TCP/UDP
(object_creation_expression
  type: (type_identifier) @cls
  (#match? @cls "^(Socket|ServerSocket|DatagramSocket)$"))
  @cap.net-egress

;; HttpURLConnection getOutputStream — explicit POST upload point
(method_invocation
  name: (identifier) @method
  (#match? @method "^(getOutputStream|getInputStream)$"))
  @cap.net-egress

;; HttpClient.send / .sendAsync — Java 11+ stdlib HTTP client
(method_invocation
  name: (identifier) @method
  (#match? @method "^(send|sendAsync)$"))
  @cap.net-egress

;; Apache HttpClient family: HttpGet / HttpPost / HttpClientBuilder
(object_creation_expression
  type: (type_identifier) @cls
  (#match? @cls "^(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|HttpHead)$"))
  @cap.net-egress

;; OkHttp: new Request.Builder().url(...).build() — Builder pattern
(method_invocation
  name: (identifier) @method
  (#match? @method "^(newCall|enqueue|execute)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; System.getenv("NAME") with literal arg
(method_invocation
  object: (identifier) @cls
  name: (identifier) @method
  arguments: (argument_list
    (string_literal (string_fragment) @env_var))
  (#eq? @cls "System")
  (#eq? @method "getenv"))

;; System.getProperty("user.home") etc. — also reads sensitive values,
;; though less commonly the credential vector. Skip to avoid noise on
;; benign property reads (java.version, os.name, ...).

;; ---- fs write outside root --------------------------------------------

;; new FileOutputStream / FileWriter / PrintWriter
(object_creation_expression
  type: (type_identifier) @cls
  (#match? @cls "^(FileOutputStream|FileWriter|PrintWriter|PrintStream|RandomAccessFile)$"))
  @cap.fs-write-outside-root

;; Files.write / writeString / copy / move (java.nio.file)
(method_invocation
  object: (identifier) @cls
  name: (identifier) @method
  (#eq? @cls "Files")
  (#match? @method "^(write|writeString|copy|move|createFile|createDirectory|createDirectories|newOutputStream|newBufferedWriter)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string_literal (string_fragment) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
