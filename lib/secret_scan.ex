defmodule SecretScan do
  @moduledoc """
  Scans directories for leaked credentials using vendored Gitleaks rules.

  See `scan/2` for the library API and `Mix.Tasks.SecretScan` for the CI task.
  """

  alias SecretScan.{Rules, Scanner}

  @typedoc """
  A detected credential.

  Paths are relative to the scanned directory, lines are one-based, and byte
  offsets are zero-based. The fingerprint is a raw HMAC-SHA256 binary. The
  matched credential itself is never included.
  """
  @type finding :: %{
          rule: String.t(),
          file_path: String.t(),
          line: pos_integer(),
          byte_offset: non_neg_integer(),
          fingerprint: binary(),
          preview: String.t()
        }

  @typedoc "A named ruleset."
  @type ruleset :: :all | :hexpm

  @typedoc "Rules to scan."
  @type rule_selection :: ruleset() | [String.t()]

  @typedoc "Rules retained first when the result limit is reached."
  @type priority_rule_selection :: :all | :hexpm | :none | [String.t()]

  @typedoc "How repeated occurrences are reported."
  @type occurrence_mode :: :all | :first_per_file

  @typedoc "How much of a matched credential appears in the preview."
  @type preview_mode :: :masked | :redacted

  @typedoc "An option accepted by `scan/2`."
  @type scan_option ::
          {:ignore, [String.t()]}
          | {:rules, rule_selection()}
          | {:priority_rules, priority_rule_selection()}
          | {:occurrences, occurrence_mode()}
          | {:preview, preview_mode()}
          | {:fingerprint_key, binary()}
          | {:file_timeout, pos_integer()}
          | {:scan_timeout, pos_integer()}
          | {:max_concurrency, pos_integer()}
          | {:max_findings, pos_integer()}
          | {:max_locations, pos_integer()}
          | {:max_path_length, pos_integer() | :infinity}

  @doc """
  Recursively scans regular files below `directory`.

  Files are streamed in overlapping windows, so scanning doesn't load a whole
  file into memory. Symbolic links and other non-regular files aren't followed.

  Returns `{findings, incomplete?}`. The second element is `true` when a file
  couldn't be read, a timeout expired, or a result limit dropped findings.
  Invalid options and a missing directory raise `ArgumentError`.

  ## Options

    * `:ignore` - path globs relative to `directory`. `*` matches within one
      path segment, `?` matches one non-separator character, and `**` crosses
      directory separators. Defaults to `[]`.

    * `:rules` - rules to run. Accepts `:all`, `:hexpm`, or a list of
      Gitleaks rule IDs. `:all` is the default. `:hexpm` is the narrower
      ruleset used for Hex.pm package notifications. Unknown IDs raise
      `ArgumentError`. See `rule_ids/1`.

    * `:priority_rules` - rules retained first if `:max_findings` is reached.
      Accepts `:all`, `:hexpm`, `:none`, or a list of rule IDs. Defaults to
      `:hexpm`. This option doesn't change which rules run.

    * `:occurrences` - `:all` reports every occurrence. `:first_per_file`
      reports the first occurrence of each credential in each file. Defaults
      to `:all`.

    * `:preview` - `:masked` shows only a fixed-width mask. `:redacted` may
      retain a short prefix and suffix. Defaults to `:masked`.

    * `:fingerprint_key` - binary HMAC key used to fingerprint credentials.
      Supply the same key to compare findings across scans. The default is a
      new random key for each scan.

    * `:file_timeout` - maximum time spent scanning one file, in milliseconds.
      Defaults to `10_000`.

    * `:scan_timeout` - maximum time for the whole scan, including directory
      traversal, in milliseconds. Defaults to `30_000`.

    * `:max_concurrency` - maximum number of files scanned concurrently.
      Defaults to `System.schedulers_online/0`.

    * `:max_findings` - maximum number of findings returned. Defaults to
      `100`. Dropped findings set `incomplete?` to `true`.

    * `:max_locations` - maximum locations returned for one credential.
      Defaults to `10`. Dropped locations set `incomplete?` to `true`.

    * `:max_path_length` - maximum length of a returned path, or `:infinity`.
      Defaults to `:infinity`.

  ## Example

      {findings, incomplete?} =
        SecretScan.scan("/workspace/my_app",
          rules: :hexpm,
          ignore: ["test/fixtures/**"],
          occurrences: :first_per_file
        )
  """
  @spec scan(Path.t(), [scan_option()]) :: {[finding()], boolean()}
  def scan(directory, opts \\ []), do: Scanner.scan_directory(directory, opts)

  @doc """
  Returns the Gitleaks rule IDs in a named ruleset.

  Pass `:all` for every vendored rule or `:hexpm` for the narrower ruleset
  used for Hex.pm package notifications.
  """
  @spec rule_ids(ruleset()) :: [String.t()]
  def rule_ids(ruleset \\ :all)

  def rule_ids(ruleset) when ruleset in [:all, :hexpm], do: Rules.rule_ids(ruleset)

  def rule_ids(ruleset) do
    raise ArgumentError, "ruleset must be :all or :hexpm, got: #{inspect(ruleset)}"
  end
end
