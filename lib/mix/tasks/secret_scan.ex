defmodule Mix.Tasks.SecretScan do
  use Mix.Task

  alias SecretScan.Scanner

  @shortdoc "Scans project files for leaked credentials"

  @moduledoc """
  Scans the current project and exits with a non-zero status when it finds a
  credential.

      mix secret_scan

  A project that isn't a Hex package selects files in its project config:

      def project do
        [
          app: :my_app,
          version: "0.1.0",
          secret_scan: [
            files: ["lib", "config", "priv"],
            rules: :hexpm,
            ignore: ["test/fixtures/**"]
          ]
        ]
      end

  When the current project defines a Hex package, the task uses the files
  selected by `package[:files]` and the ignore globs in
  `package[:secret_scan][:ignore]`. A top-level `:secret_scan` config without
  `:files` can set task options for that project, including `:rules`,
  `:priority_rules`, `:occurrences`, `:preview`, `:file_timeout`, `:scan_timeout`,
  `:max_concurrency`, `:max_findings`, `:max_locations`, and
  `:max_path_length`. See `SecretScan.scan/2` for their values, defaults, and
  behavior.
  """

  @impl Mix.Task
  def run([]) do
    with {:ok, files, opts, source} <-
           SecretScan.Project.resolve(Mix.Project.config()) do
      Mix.shell().info("Scanning #{length(files)} files from #{source_name(source)}")
      {findings, incomplete?} = Scanner.scan_files(File.cwd!(), files, opts)

      Enum.each(findings, fn finding ->
        Mix.shell().error(
          "#{finding.file_path}:#{finding.line} [#{finding.rule}] #{finding.preview}"
        )
      end)

      cond do
        findings != [] and incomplete? ->
          Mix.raise("Found #{length(findings)} leaked credentials; the scan was incomplete")

        findings != [] ->
          Mix.raise("Found #{length(findings)} leaked credentials")

        incomplete? ->
          Mix.raise("Secret scan was incomplete")

        true ->
          Mix.shell().info("No leaked credentials found")
      end
    else
      {:error, message} -> Mix.raise(message)
    end
  end

  def run(_args), do: Mix.raise("mix secret_scan doesn't accept arguments")

  defp source_name(:package), do: "the current project's Hex package config"
  defp source_name(:project), do: "the current project's secret_scan config"
end
