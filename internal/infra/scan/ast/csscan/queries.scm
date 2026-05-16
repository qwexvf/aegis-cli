; Tree-sitter queries for C# / .NET dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via
; capabilityFor() in scanner.go.
;
; Design notes:
; - C# method calls split into:
;   - bare:        (invocation_expression function: (identifier))
;   - qualified:   (invocation_expression
;                     function: (member_access_expression
;                       expression: ... name: (identifier)))
; - Type construction: (object_creation_expression type: (...) ...).
; - We match on method/identifier names; full type resolution would need
;   a Roslyn-style symbol table — out of scope. Over-trigger on common
;   method names (Get/Post/...) is the price of staying static.
; - Capability names match the suffix of domain.Capability.String().

;; ---- shell spawn -------------------------------------------------------

;; Process.Start(...) — System.Diagnostics canonical entry point.
;; Both static `Process.Start("cmd")` and instance `proc.Start()`.
(invocation_expression
  function: (member_access_expression
    name: (identifier) @method)
  (#eq? @method "Start"))
  @cap.shell-spawn

;; new Process { StartInfo = ... }.Start() — chained on object creation.
;; Caught by the Start match above.

;; new ProcessStartInfo("cmd", "args") — pre-stage for Process.Start.
(object_creation_expression
  type: (identifier) @cls
  (#eq? @cls "ProcessStartInfo"))
  @cap.shell-spawn

;; new Process(...) — instantiation pre-stage. Less common than the
;; member_access form above, but worth flagging.
(object_creation_expression
  type: (identifier) @cls
  (#eq? @cls "Process"))
  @cap.shell-spawn

;; ---- dynamic eval (C# analogue: reflection + Roslyn scripting) ---------

;; Type.GetType(...) → followed by Activator.CreateInstance / Invoke.
;; Both Activator.CreateInstance and method.Invoke are reflection RCE
;; primitives.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#eq? @cls "Activator")
  (#match? @method "^(CreateInstance|CreateInstanceFrom)$"))
  @cap.dynamic-eval

;; methodInfo.Invoke(...) — reflection invocation.
(invocation_expression
  function: (member_access_expression
    name: (identifier) @method)
  (#eq? @method "Invoke"))
  @cap.dynamic-eval

;; Roslyn / C# Scripting: CSharpScript.EvaluateAsync / RunAsync —
;; in-process eval of arbitrary C# source.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#eq? @cls "CSharpScript")
  (#match? @method "^(EvaluateAsync|RunAsync|Create)$"))
  @cap.dynamic-eval

;; Assembly.Load / LoadFrom / LoadFile — runtime assembly loading,
;; the canonical .NET equivalent to dlopen.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#eq? @cls "Assembly")
  (#match? @method "^(Load|LoadFrom|LoadFile|UnsafeLoadFrom)$"))
  @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; Convert.FromBase64String / FromBase64CharArray
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#eq? @cls "Convert")
  (#match? @method "^(FromBase64String|FromBase64CharArray|FromHexString)$"))
  @cap.base64-decode

;; ---- net egress --------------------------------------------------------

;; HttpClient member calls — GetAsync / PostAsync / SendAsync etc.
;; Match on the verb method name; over-fires on benign `obj.GetAsync()`
;; outside an HttpClient context but that's the price of no type
;; resolution.
(invocation_expression
  function: (member_access_expression
    name: (identifier) @method)
  (#match? @method "^(GetAsync|PostAsync|PutAsync|DeleteAsync|PatchAsync|SendAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync)$"))
  @cap.net-egress

;; new HttpClient(...) / new WebClient(...) — instantiation.
(object_creation_expression
  type: (identifier) @cls
  (#match? @cls "^(HttpClient|WebClient|HttpRequestMessage|HttpWebRequest)$"))
  @cap.net-egress

;; WebRequest.Create / HttpWebRequest.Create — legacy API, still
;; everywhere in real-world .NET malware samples.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#match? @cls "^(WebRequest|HttpWebRequest)$")
  (#eq? @method "Create"))
  @cap.net-egress

;; new TcpClient / TcpListener / UdpClient / Socket — raw socket egress.
(object_creation_expression
  type: (identifier) @cls
  (#match? @cls "^(TcpClient|TcpListener|UdpClient|Socket)$"))
  @cap.net-egress

;; ---- env read ----------------------------------------------------------

;; Environment.GetEnvironmentVariable("NAME") — capture the literal
;; arg for the credential-shaped-name filter.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  arguments: (argument_list
    (argument (string_literal (string_literal_content) @env_var)))
  (#eq? @cls "Environment")
  (#match? @method "^(GetEnvironmentVariable|GetEnvironmentVariables)$"))

;; ---- fs write outside root --------------------------------------------

;; File.WriteAllText / WriteAllBytes / WriteAllLines / AppendAllText etc.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#eq? @cls "File")
  (#match? @method "^(WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|AppendAllLines|Copy|Move|Replace|Create|CreateText|OpenWrite|AppendText)$"))
  @cap.fs-write-outside-root

;; new StreamWriter / FileStream(write/append) — explicit file open.
(object_creation_expression
  type: (identifier) @cls
  (#match? @cls "^(StreamWriter|BinaryWriter|FileStream)$"))
  @cap.fs-write-outside-root

;; Directory.CreateDirectory — mkdir.
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method)
  (#eq? @cls "Directory")
  (#match? @method "^(CreateDirectory|Move|Delete)$"))
  @cap.fs-write-outside-root

;; ---- raw IP literal ----------------------------------------------------

(string_literal (string_literal_content) @ip_str
  (#match? @ip_str "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
  @cap.raw-ip-literal
