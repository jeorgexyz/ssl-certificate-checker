defmodule SslCertificateChecker.MixProject do
  use Mix.Project

  def project do
    [
      app: :ssl-certificate-checker,
      version: "0.2.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        flags: [:error_handling, :race_conditions, :underspecs]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ssl, :crypto]
    ]
  end

  defp deps do
    [
      # JSON encoding/decoding for CLI
      {:jason, "~> 1.4"},

      # Development and testing
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    """
    A robust Elixir library for checking and validating SSL/TLS certificates.
    Provides detailed certificate information, expiry warnings, and validation.
    """
  end

  defp package do
    [
      name: "ssl-certificate-checker",
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/jeorgexyz/ssl-certificate-checker"
      }
    ]
  end

  defp docs do
    [
      main: "SslCertificateChecker",
      extras: ["README.md"]
    ]
  end
end
