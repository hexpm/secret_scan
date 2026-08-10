defmodule SecretScan.Project do
  @moduledoc false

  @scanner_options [
    :ignore,
    :rules,
    :priority_rules,
    :occurrences,
    :preview,
    :file_timeout,
    :scan_timeout,
    :max_concurrency,
    :max_findings,
    :max_locations,
    :max_path_length
  ]
  @default_package_files ~w(lib priv .formatter.exs mix.exs README* readme* LICENSE* license*
                            CHANGELOG* changelog* src c_src Makefile*)

  def resolve(config, root \\ File.cwd!()) do
    scan_config = config |> Keyword.get(:secret_scan, []) |> validate_config!(:secret_scan)

    case Keyword.fetch(scan_config, :files) do
      {:ok, patterns} ->
        files = root |> expand_files(patterns, match_dot: true) |> require_files!(:project)
        {:ok, files, scanner_options(scan_config), :project}

      :error ->
        resolve_package(config, scan_config, root)
    end
  end

  defp resolve_package(config, scan_config, root) do
    if Keyword.has_key?(config, :package) do
      package_config = config |> Keyword.fetch!(:package) |> validate_config!(:package)

      secret_scan =
        package_config |> Keyword.get(:secret_scan, []) |> validate_config!(:package_secret_scan)

      files =
        root
        |> expand_files(Keyword.get(package_config, :files, @default_package_files))
        |> exclude_package_files(Keyword.get(package_config, :exclude_patterns, []))
        |> require_files!(:package)

      opts =
        scan_config
        |> scanner_options()
        |> Keyword.update(
          :ignore,
          Keyword.get(secret_scan, :ignore, []),
          &(Keyword.get(secret_scan, :ignore, []) ++ &1)
        )

      {:ok, files, opts, :package}
    else
      {:error,
       "configure secret_scan: [files: [...]] in mix.exs because this project has no Hex package config"}
    end
  end

  defp validate_config!(config, name) when is_list(config) do
    if Keyword.keyword?(config) do
      config
    else
      Mix.raise("#{name} must be a keyword list")
    end
  end

  defp validate_config!(nil, _name), do: []
  defp validate_config!(_config, name), do: Mix.raise("#{name} must be a keyword list")

  defp scanner_options(config), do: Keyword.take(config, @scanner_options)

  defp exclude_package_files(files, patterns) when is_list(patterns) do
    Enum.reject(files, fn path ->
      Path.basename(path) == ".DS_Store" or Enum.any?(patterns, &(path =~ &1))
    end)
  end

  defp exclude_package_files(_files, patterns),
    do: Mix.raise("package :exclude_patterns must be a list, got: #{inspect(patterns)}")

  defp require_files!([], :package), do: Mix.raise("the Hex package contains no files to scan")

  defp require_files!([], :project),
    do: Mix.raise("secret_scan :files didn't match any regular files")

  defp require_files!(files, _source), do: files

  defp expand_files(root, patterns, opts \\ [])

  defp expand_files(root, patterns, opts) when is_list(patterns) do
    match_dot? = Keyword.get(opts, :match_dot, false)

    patterns
    |> Enum.flat_map(fn
      pattern when is_binary(pattern) ->
        Path.wildcard(Path.join(root, pattern), match_dot: match_dot?)

      pattern ->
        Mix.raise("secret_scan :files entries must be strings, got: #{inspect(pattern)}")
    end)
    |> Enum.flat_map(&regular_files/1)
    |> Enum.uniq()
    |> Enum.map(fn path ->
      relative = Path.relative_to(path, root)

      case Path.safe_relative(relative) do
        {:ok, relative} ->
          relative

        :error ->
          Mix.raise("secret_scan :files must stay inside the project root, got: #{path}")
      end
    end)
    |> Enum.sort()
  end

  defp expand_files(_root, patterns, _opts),
    do: Mix.raise("secret_scan :files must be a list, got: #{inspect(patterns)}")

  defp regular_files(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular}} ->
        [path]

      {:ok, %File.Stat{type: :directory}} ->
        path
        |> File.ls!()
        |> Enum.flat_map(&regular_files(Path.join(path, &1)))

      _ ->
        []
    end
  end
end
