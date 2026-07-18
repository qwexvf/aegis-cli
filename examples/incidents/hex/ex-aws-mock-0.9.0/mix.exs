defmodule ExAwsMock.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_aws_mock,
      version: "0.9.0",
      elixir: "~> 1.14",
      description: "AWS SDK mock for testing (typosquat of ex_aws)",
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger], mod: {ExAwsMock.Application, []}]
  end

  defp deps do
    [{:jason, "~> 1.4"}]
  end
end
