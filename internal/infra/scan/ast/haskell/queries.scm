; Tree-sitter queries for Haskell dangerous-pattern detection.
; Each "@cap.X" capture maps to a domain.Capability via capabilityFor().
;
; Haskell function calls parse as `apply` with curried `variable` /
; `qualified` parts. We match on bare `variable` text — qualified
; references (e.g. System.Process.callCommand) also expose the final
; identifier as a `variable` node, so the same query catches both.

;; ---- shell spawn -------------------------------------------------------

;; System.Process — callCommand / callProcess / createProcess /
;; runCommand / runProcess / spawnCommand / spawnProcess /
;; readProcess / readProcessWithExitCode / readCreateProcess
((variable) @cap.shell-spawn
  (#match? @cap.shell-spawn "^(callCommand|callProcess|createProcess|runCommand|runProcess|spawnCommand|spawnProcess|readProcess|readProcessWithExitCode|readCreateProcess|readCreateProcessWithExitCode|withCreateProcess)$"))

;; ---- dynamic eval ------------------------------------------------------

;; unsafePerformIO, unsafeCoerce — escape hatches that bypass the
;; type system; common in malware to hide IO inside pure-looking code.
((variable) @cap.dynamic-eval
  (#match? @cap.dynamic-eval "^(unsafePerformIO|unsafeCoerce|unsafeDupablePerformIO|unsafeInterleaveIO)$"))

;; FFI: `foreign import` declarations bypass type safety entirely.
(foreign_import) @cap.dynamic-eval

;; ---- base64 decode -----------------------------------------------------

;; Data.ByteString.Base64.{decode,decodeLenient,decodeBase64}
((variable) @cap.base64-decode
  (#match? @cap.base64-decode "^(decode|decodeLenient|decodeBase64|decodeBase64Lenient)$"))

;; ---- net egress --------------------------------------------------------

;; HTTP clients: Network.HTTP / Network.HTTP.Simple / http-conduit /
;; Network.Wreq
((variable) @cap.net-egress
  (#match? @cap.net-egress "^(httpLBS|httpBS|httpJSON|httpJSONEither|httpSink|httpSource|httpNoBody|simpleHTTP|getResponseBody|sendHTTP)$"))

;; Wreq-style HTTP verbs (also overlap with Servant / Yesod request
;; handlers — accept false positives in framework code).
((variable) @cap.net-egress
  (#match? @cap.net-egress "^(getWith|postWith|putWith|deleteWith|patchWith|optionsWith|customMethodWith)$"))

;; Network.Socket — raw sockets.
((variable) @cap.net-egress
  (#match? @cap.net-egress "^(socket|connect|bind|listen|sendAll|recvAll|getAddrInfo)$"))

;; ---- env read ----------------------------------------------------------

;; System.Environment
((variable) @cap.env-read
  (#match? @cap.env-read "^(getEnv|lookupEnv|getEnvironment)$"))

;; ---- fs write outside root --------------------------------------------

;; System.IO / Data.ByteString — file write APIs.
((variable) @cap.fs-write-outside-root
  (#match? @cap.fs-write-outside-root "^(writeFile|appendFile|hPutStr|hPutStrLn|hPutBuf|hPrint|writeBinaryFile)$"))

;; openFile mode arguments (WriteMode / AppendMode / ReadWriteMode) —
;; conservative: just flag any openFile call.
((variable) @cap.fs-write-outside-root
  (#match? @cap.fs-write-outside-root "^(openFile|openBinaryFile|withFile)$"))

;; ---- raw IP literal ----------------------------------------------------

((string) @cap.raw-ip-literal
  (#match? @cap.raw-ip-literal "https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))
