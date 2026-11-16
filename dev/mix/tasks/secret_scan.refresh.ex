defmodule Mix.Tasks.SecretScan.Refresh do
  @shortdoc "Refreshes the vendored gitleaks secret-scanning ruleset"

  @moduledoc """
  Rewrites `rules/gitleaks.toml`, `rules/LICENSE.gitleaks`, and
  `rules/SOURCE` from the latest upstream revision.

  Pass `--check-outdated` to exit with status 100 when any vendored source
  differs from that revision.

  Set `GH_TOKEN` to authenticate the GitHub API request that looks up the
  revision.

      mix secret_scan.refresh
      mix secret_scan.refresh --check-outdated
  """
  use Mix.Task

  @dir Path.expand("../../../rules", __DIR__)
  @raw "https://raw.githubusercontent.com/gitleaks/gitleaks"
  @commits "https://api.github.com/repos/gitleaks/gitleaks/commits?path=config/gitleaks.toml&per_page=1"
  @source_repository "https://github.com/gitleaks/gitleaks"

  # Shapes GitHub secret scanning reports. Each one is anchored tightly enough
  # that it only matches a written-out key, never a rule's regex: every rule
  # puts a metacharacter straight after its prefix.
  @literal_patterns [
    "AIza[0-9A-Za-z_-]{35}",
    "gh[oprsu]_[0-9A-Za-z]{36}",
    "xox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z-]{10,}",
    "AKIA[0-9A-Z]{16}"
  ]

  @impl Mix.Task
  def run(args) when args in [[], ["--check-outdated"]] do
    Application.ensure_all_started(:req)
    {sha, date} = latest_commit!()
    urls = source_urls(sha)

    config = fetch!(urls.config) |> normalize_final_newline() |> defang()
    license = fetch!(urls.license) |> normalize_final_newline()
    source = source_metadata(sha, date)

    if args == ["--check-outdated"] do
      validate_sources!(config, license)

      if outdated?(@dir, config, license, source) do
        Mix.raise("Vendored gitleaks rules are outdated. Run `mix secret_scan.refresh`.",
          exit_status: 100
        )
      end

      Mix.shell().info("Vendored gitleaks rules are current.")
    else
      install!(@dir, config, license, source)

      Mix.shell().info(
        "Vendored gitleaks ruleset from #{String.slice(sha, 0, 12)} (#{String.slice(date, 0, 10)})."
      )
    end
  end

  def run(_args) do
    Mix.raise("Invalid arguments. See `mix help secret_scan.refresh`.")
  end

  @doc false
  def source_urls(sha) when is_binary(sha) do
    %{
      config: "#{@raw}/#{sha}/config/gitleaks.toml",
      license: "#{@raw}/#{sha}/LICENSE"
    }
  end

  @doc false
  def source_metadata(sha, date) when is_binary(sha) and is_binary(date) do
    """
    repository: #{@source_repository}
    commit: #{sha}
    date: #{String.slice(date, 0, 10)}
    """
  end

  @doc false
  def outdated?(dir, config, license, source) do
    Enum.any?(
      [
        {"gitleaks.toml", config},
        {"LICENSE.gitleaks", license},
        {"SOURCE", source}
      ],
      fn {filename, expected} ->
        File.read(Path.join(dir, filename)) != {:ok, expected}
      end
    )
  end

  @doc false
  def install!(dir, config, license, source)
      when is_binary(config) and is_binary(license) and is_binary(source) do
    validate_sources!(config, license)

    suffix = System.unique_integer([:positive])
    staged = "#{dir}.tmp-#{suffix}"
    backup = "#{dir}.backup-#{suffix}"

    File.cp_r!(dir, staged)

    try do
      File.write!(Path.join(staged, "gitleaks.toml"), config, [:binary])
      File.write!(Path.join(staged, "LICENSE.gitleaks"), license, [:binary])
      File.write!(Path.join(staged, "SOURCE"), source, [:binary])
      File.rename!(dir, backup)

      try do
        File.rename!(staged, dir)
      rescue
        exception ->
          File.rename!(backup, dir)
          reraise exception, __STACKTRACE__
      end

      File.rm_rf!(backup)
    after
      File.rm_rf(staged)
    end

    Mix.shell().info("wrote #{Path.join(dir, "gitleaks.toml")} (#{byte_size(config)} bytes)")

    Mix.shell().info("wrote #{Path.join(dir, "LICENSE.gitleaks")} (#{byte_size(license)} bytes)")
    Mix.shell().info("wrote #{Path.join(dir, "SOURCE")} (#{byte_size(source)} bytes)")

    :ok
  end

  @doc """
  Wraps the last byte of any literal credential in a character class.

  gitleaks allowlists example keys by writing them out in full, so vendoring
  the config puts strings like a GCP key into our repository and GitHub's own
  secret scanning opens an alert for each one. The entries are regexes, so
  `[7]` and `7` are the same pattern and the allowlist keeps working, but the
  file no longer holds a contiguous literal for a scanner to match.

  A shape upstream adds that is not listed here gets alerted on again, and the
  fix is another entry.
  """
  def defang(toml) do
    Enum.reduce(@literal_patterns, toml, fn source, acc ->
      pattern = Regex.compile!(source)

      Regex.replace(pattern, acc, fn match ->
        {head, <<last::binary-size(1)>>} = String.split_at(match, -1)
        "#{head}[#{last}]"
      end)
    end)
  end

  @doc false
  def api_options(nil), do: []
  def api_options(""), do: []
  def api_options(token) when is_binary(token), do: [auth: {:bearer, token}]

  defp fetch!(url) do
    %{status: 200, body: body} = apply(Req, :get!, [url, [decode_body: false]])
    body
  end

  defp normalize_final_newline(contents) do
    String.trim_trailing(contents) <> "\n"
  end

  defp latest_commit! do
    %{status: 200, body: [%{"sha" => sha, "commit" => commit} | _]} =
      apply(Req, :get!, [@commits, api_options(System.get_env("GH_TOKEN"))])

    {sha, commit["committer"]["date"]}
  end

  defp validate_sources!(config, license) do
    parsed = SecretScan.RuleSource.decode!(config)
    validate_hexpm_rules!(parsed)

    if byte_size(license) == 0 do
      raise ArgumentError, "gitleaks license is empty"
    end
  end

  defp validate_hexpm_rules!(%{"rules" => rules}) do
    ids = MapSet.new(rules, & &1["id"])
    missing = Enum.reject(SecretScan.Rules.hexpm_rule_ids(), &MapSet.member?(ids, &1))

    if missing != [] do
      raise ArgumentError, "gitleaks config removed Hexpm rules: #{Enum.join(missing, ", ")}"
    end
  end
end
