defmodule SecretScan.RuleSource do
  @moduledoc false

  @supported_min_version "v8.25.0"
  @root_fields ~w(allowlist minVersion rules title)
  @rule_fields ~w(allowlists description entropy id keywords path regex secretGroup)
  @allowlist_fields ~w(condition description paths regexTarget regexes stopwords)

  def decode!(toml, filename \\ "gitleaks.toml") when is_binary(toml) do
    parsed = Toml.decode!(toml, filename: filename)
    validate!(parsed)
  end

  def validate!(parsed) when is_map(parsed) do
    validate_keys!(parsed, @root_fields, "config")

    unless parsed["minVersion"] == @supported_min_version do
      raise ArgumentError,
            "unsupported gitleaks minVersion #{inspect(parsed["minVersion"])}; " <>
              "expected #{@supported_min_version}"
    end

    validate_allowlist!(Map.fetch!(parsed, "allowlist"), "global allowlist")

    case Map.fetch!(parsed, "rules") do
      [] ->
        raise ArgumentError, "gitleaks config contains no rules"

      rules when is_list(rules) ->
        Enum.each(rules, &validate_rule!/1)
        validate_unique_ids!(rules)

      rules ->
        raise ArgumentError, "gitleaks rules must be a list, got: #{inspect(rules)}"
    end

    parsed
  end

  defp validate_rule!(rule) when is_map(rule) do
    validate_keys!(rule, @rule_fields, "rule #{inspect(rule["id"])}")

    unless is_binary(rule["id"]) and is_binary(rule["description"]) do
      raise ArgumentError, "gitleaks rules require string id and description fields"
    end

    unless is_binary(rule["regex"]) or is_binary(rule["path"]) do
      raise ArgumentError, "gitleaks rule #{inspect(rule["id"])} requires regex or path"
    end

    context = "rule #{inspect(rule["id"])}"
    validate_optional_string_list!(rule, "keywords", context)
    validate_optional_number!(rule, "entropy", context)
    validate_optional_integer!(rule, "secretGroup", context)
    compile_optional_pattern!(rule, "regex", context)
    compile_optional_pattern!(rule, "path", context)

    case Map.get(rule, "allowlists", []) do
      allowlists when is_list(allowlists) ->
        Enum.each(allowlists, &validate_allowlist!(&1, "allowlist for #{context}"))

      allowlists ->
        raise ArgumentError,
              "allowlists for #{context} must be a list, got: #{inspect(allowlists)}"
    end
  end

  defp validate_rule!(rule),
    do: raise(ArgumentError, "gitleaks rule must be a table, got: #{inspect(rule)}")

  defp validate_allowlist!(allowlist, context) when is_map(allowlist) do
    validate_keys!(allowlist, @allowlist_fields, context)

    unless allowlist["condition"] in [nil, "OR", "AND"] do
      raise ArgumentError,
            "unsupported condition in #{context}: #{inspect(allowlist["condition"])}"
    end

    unless allowlist["regexTarget"] in [nil, "secret", "match", "line"] do
      raise ArgumentError,
            "unsupported regexTarget in #{context}: #{inspect(allowlist["regexTarget"])}"
    end

    validate_optional_string_list!(allowlist, "paths", context)
    validate_optional_string_list!(allowlist, "regexes", context)
    validate_optional_string_list!(allowlist, "stopwords", context)

    Enum.each(Map.get(allowlist, "paths", []), &compile_pattern!(&1, context))
    Enum.each(Map.get(allowlist, "regexes", []), &compile_pattern!(&1, context))
  end

  defp validate_allowlist!(allowlist, context),
    do: raise(ArgumentError, "#{context} must be a table, got: #{inspect(allowlist)}")

  defp validate_keys!(map, supported, context) do
    case Map.keys(map) -- supported do
      [] ->
        :ok

      fields ->
        raise ArgumentError, "unsupported fields in #{context}: #{Enum.join(fields, ", ")}"
    end
  end

  defp validate_unique_ids!(rules) do
    duplicates =
      rules
      |> Enum.map(& &1["id"])
      |> Enum.frequencies()
      |> Enum.filter(&(elem(&1, 1) > 1))
      |> Enum.map(&elem(&1, 0))

    if duplicates != [] do
      raise ArgumentError, "duplicate gitleaks rule ids: #{Enum.join(duplicates, ", ")}"
    end
  end

  defp validate_optional_string_list!(map, field, context) do
    case Map.get(map, field, []) do
      values when is_list(values) ->
        case Enum.find(values, &(not is_binary(&1) or &1 == "")) do
          nil ->
            :ok

          value ->
            raise ArgumentError,
                  "#{field} in #{context} contains an invalid value: #{inspect(value)}"
        end

      values ->
        raise ArgumentError, "#{field} in #{context} must be a list, got: #{inspect(values)}"
    end
  end

  defp validate_optional_number!(map, field, context) do
    case Map.get(map, field) do
      nil ->
        :ok

      value when is_number(value) ->
        :ok

      value ->
        raise ArgumentError, "#{field} in #{context} must be a number, got: #{inspect(value)}"
    end
  end

  defp validate_optional_integer!(map, field, context) do
    case Map.get(map, field) do
      nil ->
        :ok

      value when is_integer(value) and value >= 0 ->
        :ok

      value ->
        raise ArgumentError, "#{field} in #{context} must be an integer, got: #{inspect(value)}"
    end
  end

  defp compile_optional_pattern!(map, field, context) do
    case Map.get(map, field) do
      nil -> :ok
      pattern -> compile_pattern!(pattern, context)
    end
  end

  defp compile_pattern!(pattern, context) do
    result = if is_binary(pattern), do: Regex.compile(pattern), else: :invalid

    case result do
      {:ok, _regex} ->
        :ok

      {:error, reason} ->
        raise ArgumentError, "invalid regex in #{context}: #{inspect(reason)}"

      :invalid ->
        raise ArgumentError, "regex in #{context} must be a string, got: #{inspect(pattern)}"
    end
  end
end
