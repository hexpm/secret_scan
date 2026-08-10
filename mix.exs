defmodule SecretScan.MixProject do
  use Mix.Project

  @source_url "https://github.com/hexpm/secret_scan"

  def project do
    [
      app: :secret_scan,
      version: version(),
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      description: "Detect leaked credentials in project directories",
      source_url: @source_url,
      deps: deps(),
      package: package(),
      docs: [
        main: "readme",
        extras: ["README.md"],
        source_ref: "v#{version()}"
      ]
    ]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  defp elixirc_paths(env) when env in [:dev, :test], do: ["lib", "dev"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:toml, "~> 0.7", runtime: false},
      {:req, "~> 0.6", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      files: ~w(lib rules .formatter.exs mix.exs README.md LICENSE CHANGELOG.md VERSION),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp version do
    "VERSION"
    |> File.read!()
    |> String.trim()
  end
end
