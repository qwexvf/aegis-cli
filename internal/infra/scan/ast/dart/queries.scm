; Tree-sitter queries for Dart dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via capabilityFor().
;
; Conservative approach: match identifier names of known dangerous APIs.
; Some false positives possible when an identifier shadows the API name
; without invoking it; acceptable for a security scanner.

;; ---- shell spawn -------------------------------------------------------

;; Process.run / Process.start / Process.runSync / Process.killPid.
;; tree-sitter-dart parses `Process` in `Process.run(...)` as a plain
;; identifier in the receiver position, so we match identifier.
((identifier) @cap.shell-spawn
  (#match? @cap.shell-spawn "^(Process|runSync|killPid)$"))

;; ---- dynamic eval ------------------------------------------------------

;; Function.apply — dart's primary dynamic dispatch.
((identifier) @cap.dynamic-eval
  (#match? @cap.dynamic-eval "^(apply|invoke|noSuchMethod)$"))

;; dart:mirrors — reflection / metaprogramming.
((identifier) @cap.dynamic-eval
  (#match? @cap.dynamic-eval "^(ClassMirror|InstanceMirror|MirrorSystem|reflect|reflectClass|reflectType)$"))

;; ---- base64 decode -----------------------------------------------------

((identifier) @cap.base64-decode
  (#match? @cap.base64-decode "^(base64Decode|base64UrlDecode)$"))

;; base64.decode / Base64Codec.decode
((identifier) @cap.base64-decode
  (#match? @cap.base64-decode "^(Base64Codec|Base64Decoder)$"))

;; ---- net egress --------------------------------------------------------

;; HttpClient / RawSecureSocket / Socket / WebSocket — dart:io
((identifier) @cap.net-egress
  (#match? @cap.net-egress "^(HttpClient|HttpRequest|HttpClientRequest|RawSocket|Socket|SecureSocket|RawSecureSocket|WebSocket|HttpServer|InternetAddress)$"))

;; Methods like .get/.post on HTTP clients — package:http style.
((identifier) @cap.net-egress
  (#match? @cap.net-egress "^(getUrl|postUrl|putUrl|deleteUrl|patchUrl|openUrl)$"))

;; ---- env read ----------------------------------------------------------

;; Platform.environment / String.fromEnvironment / Platform.script
((identifier) @cap.env-read
  (#match? @cap.env-read "^(Platform|fromEnvironment|environment)$"))

;; ---- fs write outside root --------------------------------------------

;; File class and write methods.
((identifier) @cap.fs-write-outside-root
  (#match? @cap.fs-write-outside-root "^(writeAsString|writeAsBytes|writeAsStringSync|writeAsBytesSync|openWrite|writeFrom)$"))

;; ---- raw IP literal ----------------------------------------------------

((string_literal) @cap.raw-ip-literal
  (#match? @cap.raw-ip-literal "https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
