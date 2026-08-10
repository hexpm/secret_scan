defmodule SecretScan.Rules do
  @moduledoc false

  # Rules come from the vendored Gitleaks config. The TOML is parsed at compile
  # time into plain data. Regexes and the keyword matcher are built once at
  # runtime because compiled patterns can't be stored in module attributes.

  # Read only at compile time. `mix secret_scan.refresh` rewrites it.
  @gitleaks_config Path.expand("../../rules/gitleaks.toml", __DIR__)

  @external_resource @gitleaks_config

  # The named subset used by Hex.pm for owner notifications. gitleaks
  # is tuned for CI on your own repo, where a false positive costs a developer
  # half a minute. A service sending unsolicited security email needs a narrower
  # set, so a rule only graduates after review against published packages.
  #
  # Membership is decided by how a rule is written, not by how often it fired
  # on the packages already published. A scan of all 163,630 existing releases
  # produced hits for 7 of these rules and nothing at all for the rest, which
  # is far too small a sample to say anything about precision, and the existing
  # corpus is the wrong population anyway: it is weighted toward old and
  # abandoned packages, where a fake token in a README was normal.
  #
  # Excluded because of what the pattern does:
  #
  #   the 18 rules shaped `[\w.-]{0,50}?(?:vendor)...=...(value)` are
  #     generic-api-key with a vendor word in front, and generic-api-key is
  #     already record-only for that reason. atlassian-api-token is the one
  #     worth splitting: its other branch, ATATT3 plus 186 characters, is as
  #     self-identifying as anything here.
  #   gcp-api-key            precise, but a Google API key is routinely shipped
  #                          in client code on purpose
  #   confluent-access-token another of the contextual shape: any sixteen
  #                          lowercase alphanumerics near the word "confluent",
  #                          which is why it matched a C++ identifier in duckdb
  #   private-key            fires on every test fixture that ships a PEM
  #   pkcs12-file            matches a filename and never looks inside
  #
  # stripe-access-token is included though its corpus hits were placeholder keys
  # in READMEs: a leaked sk_test_ still lets someone write to the owner's Stripe
  # test environment, so it is worth an email despite the false positive rate.
  @hexpm_rules ~w(
    adobe-client-secret
    age-secret-key
    alibaba-access-key-id
    anthropic-admin-api-key
    anthropic-api-key
    azure-ad-client-secret
    aws-access-token
    clojars-api-token
    stripe-access-token
    databricks-api-token
    digitalocean-access-token
    digitalocean-pat
    digitalocean-refresh-token
    doppler-api-token
    duffel-api-token
    dynatrace-api-token
    easypost-api-token
    flutterwave-secret-key
    frameio-api-token
    github-app-token
    github-fine-grained-pat
    github-oauth
    github-pat
    github-refresh-token
    gitlab-pat
    gitlab-ptt
    gitlab-rrt
    grafana-api-key
    grafana-cloud-api-token
    grafana-service-account-token
    intra42-client-secret
    linear-api-key
    npm-access-token
    openai-api-key
    planetscale-api-token
    planetscale-oauth-token
    planetscale-password
    postman-api-token
    prefect-api-token
    pulumi-api-token
    pypi-upload-token
    rubygems-api-token
    scalingo-api-token
    sendgrid-api-token
    sendinblue-api-token
    shippo-api-token
    shopify-access-token
    shopify-custom-access-token
    shopify-private-app-access-token
    shopify-shared-secret
    slack-app-token
    slack-bot-token
    slack-config-access-token
    slack-config-refresh-token
    slack-legacy-bot-token
    slack-legacy-token
    slack-legacy-workspace-token
    slack-user-token
    slack-webhook-url
    square-access-token
    twilio-api-key
    vault-batch-token
    vault-service-token
  )

  @parsed @gitleaks_config |> File.read!() |> SecretScan.RuleSource.decode!(@gitleaks_config)

  @raw_rules Map.fetch!(@parsed, "rules")
  @raw_global [Map.fetch!(@parsed, "allowlist")]
  @source_hash :erlang.md5(
                 :erlang.term_to_binary({
                   @raw_rules,
                   @raw_global,
                   @hexpm_rules,
                   File.read!(__ENV__.file)
                 })
               )
  @persistent_key {__MODULE__, :compiled}

  if @raw_rules == [] do
    raise "no secret scanning rules were loaded from #{@gitleaks_config}"
  end

  duplicate_ids =
    @raw_rules |> Enum.map(& &1["id"]) |> Enum.frequencies() |> Enum.filter(&(elem(&1, 1) > 1))

  if duplicate_ids != [] do
    raise "duplicate secret scanning rule ids: #{inspect(Enum.map(duplicate_ids, &elem(&1, 0)))}"
  end

  unknown_hexpm_rules = @hexpm_rules -- Enum.map(@raw_rules, & &1["id"])

  if unknown_hexpm_rules != [] do
    raise "Hexpm rules do not exist: #{inspect(unknown_hexpm_rules)}"
  end

  # Returns every compiled rule for the scanner and internal validation.
  def all, do: compiled().rules

  def rule_ids(:all), do: Enum.map(@raw_rules, & &1["id"])
  def rule_ids(:hexpm), do: @hexpm_rules

  # These rules match on the file path alone, with no content regex.
  def path_rules(selection \\ :all), do: select(compiled().path_rules, selection)

  def global_allowlists, do: compiled().global_allowlists

  def hexpm?(rule_id), do: MapSet.member?(compiled().hexpm, rule_id)

  def hexpm_rule_ids, do: @hexpm_rules

  # Unknown IDs raise so a misspelled CI rule can't silently disable scanning.
  def resolve!(:all), do: :all
  def resolve!(:hexpm), do: compiled().hexpm

  def resolve!(rule_ids) when is_list(rule_ids) do
    unless Enum.all?(rule_ids, &is_binary/1) do
      raise ArgumentError, ":rules must contain only Gitleaks rule ids"
    end

    known = MapSet.new(compiled().rules, & &1.id)
    unknown = Enum.reject(rule_ids, &MapSet.member?(known, &1))

    if unknown != [] do
      raise ArgumentError, "unknown Gitleaks rules: #{Enum.join(unknown, ", ")}"
    end

    MapSet.new(rule_ids)
  end

  def resolve!(other) do
    raise ArgumentError,
          ":rules must be :all, :hexpm, or a list of Gitleaks rule ids, got: #{inspect(other)}"
  end

  def resolve_priority!(:none), do: :none
  def resolve_priority!(:all), do: :all
  def resolve_priority!(:hexpm), do: compiled().hexpm
  def resolve_priority!(rule_ids) when is_list(rule_ids), do: resolve!(rule_ids)

  def resolve_priority!(other) do
    raise ArgumentError,
          ":priority_rules must be :all, :hexpm, :none, or a list of Gitleaks rule ids, got: #{inspect(other)}"
  end

  # Some rules only apply to a particular file type, such as NuGet passwords
  # in nuget.config and Terraform passwords in .tf files.
  def for_path(path, selection \\ :all) do
    compiled().content_rules
    |> select(selection)
    |> Enum.filter(fn rule -> is_nil(rule.path) or Regex.match?(rule.path, path) end)
  end

  defp select(rules, :all), do: rules
  defp select(rules, selected), do: Enum.filter(rules, &MapSet.member?(selected, &1.id))

  # Narrows rules to those whose declared keywords appear in the content.
  # This leaves only a few regexes to run for most source files.
  def candidates(rules, content) do
    %{keyword_pattern: pattern} = compiled()
    lowered = ascii_downcase(content)

    %{keyword_containment: containment} = compiled()

    present = present_keywords(lowered, pattern, containment, 0, MapSet.new())

    Enum.filter(rules, fn rule ->
      rule.keywords == [] or Enum.any?(rule.keywords, &MapSet.member?(present, &1))
    end)
  end

  # The binary matcher returns non-overlapping matches. Restarting one byte
  # after each match preserves overlaps such as `sk` at byte zero and `key` at
  # byte one. Closing each match over contained keywords also preserves a
  # shorter keyword at the same start position.
  defp present_keywords(content, pattern, containment, offset, present)
       when offset < byte_size(content) do
    scope = {offset, byte_size(content) - offset}

    case :binary.match(content, pattern, scope: scope) do
      {start, length} ->
        present =
          content
          |> binary_part(start, length)
          |> with_contained(containment)
          |> Enum.reduce(present, &MapSet.put(&2, &1))

        present_keywords(content, pattern, containment, start + 1, present)

      :nomatch ->
        present
    end
  end

  defp present_keywords(_content, _pattern, _containment, _offset, present), do: present

  defp with_contained(keyword, containment) do
    Map.get(containment, keyword, [keyword])
  end

  # Shannon entropy in bits per byte, using the same formula as Gitleaks.
  def entropy(""), do: 0.0

  def entropy(string) do
    bytes = :binary.bin_to_list(string)
    total = length(bytes)

    bytes
    |> Enum.frequencies()
    |> Enum.reduce(0.0, fn {_byte, count}, acc ->
      probability = count / total
      acc - probability * :math.log2(probability)
    end)
  end

  def allowed_path?(path) do
    Enum.any?(compiled().global_allowlists, fn allowlist ->
      Enum.any?(allowlist.paths, &Regex.match?(&1, path))
    end)
  end

  # Regexes test the configured target, paths test the file path, and stopwords
  # test the secret. AND requires every configured criterion; OR requires one.
  def allowed?(allowlists, targets) do
    Enum.any?(allowlists, &allowlist_matches?(&1, targets))
  end

  defp allowlist_matches?(allowlist, targets) do
    # Only criteria the allowlist actually configures count. An `AND` allowlist
    # that sets paths and regexes needs both, but must not be held to stopwords
    # it never declared.
    checks =
      [
        check(allowlist.paths != [], fn ->
          Enum.any?(allowlist.paths, &Regex.match?(&1, targets.path))
        end),
        check(allowlist.regexes != [], fn ->
          target = target(targets, allowlist.regex_target)
          Enum.any?(allowlist.regexes, &Regex.match?(&1, target))
        end),
        check(allowlist.stopword_pattern, fn ->
          :binary.match(ascii_downcase(targets.secret), allowlist.stopword_pattern) != :nomatch
        end)
      ]
      |> Enum.reject(&is_nil/1)

    case {allowlist.condition, checks} do
      {_condition, []} -> false
      {:and, checks} -> Enum.all?(checks)
      {:or, checks} -> Enum.any?(checks)
    end
  end

  defp check(configured, fun), do: if(configured, do: fun.(), else: nil)

  defp target(targets, :secret), do: targets.secret
  defp target(targets, :match), do: targets.match
  defp target(targets, :line), do: targets.line

  # Keywords and stopwords are ASCII. Lowercasing byte by byte preserves
  # offsets and works for binary files that aren't valid UTF-8.
  def ascii_downcase(binary) do
    for <<byte <- binary>>, into: <<>> do
      if byte >= ?A and byte <= ?Z, do: <<byte + 32>>, else: <<byte>>
    end
  end

  defp compiled do
    case :persistent_term.get(@persistent_key, nil) do
      {@source_hash, compiled} -> compiled
      _other -> build()
    end
  end

  defp build do
    rules = Enum.map(@raw_rules, &compile_rule/1)
    {content_rules, path_rules} = Enum.split_with(rules, &(&1.regex != nil))
    keywords = rules |> Enum.flat_map(& &1.keywords) |> Enum.uniq()

    compiled = %{
      rules: rules,
      content_rules: content_rules,
      path_rules: path_rules,
      global_allowlists: Enum.map(@raw_global, &compile_allowlist/1),
      hexpm: MapSet.new(@hexpm_rules),
      keyword_pattern: :binary.compile_pattern(keywords),
      keyword_containment: containment(keywords)
    }

    :persistent_term.put(@persistent_key, {@source_hash, compiled})
    compiled
  end

  defp containment(keywords) do
    Map.new(keywords, fn keyword ->
      {keyword, Enum.filter(keywords, &String.contains?(keyword, &1))}
    end)
  end

  defp compile_rule(raw) do
    regex = raw["regex"] && Regex.compile!(raw["regex"])

    %{
      id: raw["id"],
      description: raw["description"],
      regex: regex,
      path: raw["path"] && Regex.compile!(raw["path"]),
      keywords: raw |> Map.get("keywords", []) |> Enum.map(&ascii_downcase/1),
      entropy: raw["entropy"] && raw["entropy"] / 1,
      secret_group: raw["secretGroup"],
      allowlists: raw |> Map.get("allowlists", []) |> Enum.map(&compile_allowlist/1)
    }
  end

  defp compile_allowlist(raw) do
    stopwords = raw |> Map.get("stopwords", []) |> Enum.map(&ascii_downcase/1)

    %{
      paths: raw |> Map.get("paths", []) |> Enum.map(&Regex.compile!/1),
      regexes: raw |> Map.get("regexes", []) |> Enum.map(&Regex.compile!/1),
      stopword_pattern: stopwords != [] && :binary.compile_pattern(stopwords),
      regex_target: regex_target(raw["regexTarget"]),
      condition: condition(raw["condition"])
    }
  end

  defp regex_target(nil), do: :secret
  defp regex_target("secret"), do: :secret
  defp regex_target("match"), do: :match
  defp regex_target("line"), do: :line

  defp condition(nil), do: :or
  defp condition("OR"), do: :or
  defp condition("AND"), do: :and
end
