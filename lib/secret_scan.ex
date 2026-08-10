defmodule SecretScan do
  @moduledoc """
  Detects credentials in a directory.

  `scan/2` recursively scans regular files below the given directory. It
  returns a list of findings without raw credentials and a boolean indicating
  whether a file error, timeout, or result limit made the result incomplete.

      {findings, incomplete?} =
        SecretScan.scan("/workspace/my_app",
          rules: :hexpm,
          ignore: ["test/fixtures/**"]
        )

  The raw credential isn't returned. Each finding contains its rule, location,
  masked or redacted preview, and an HMAC fingerprint. Pass `:fingerprint_key`
  when fingerprints must remain stable across scans. Without it, each scan
  uses a new random key.

  `:rules` accepts `:all`, the narrower `:hexpm` ruleset used for Hex.pm
  package notifications, or a list of Gitleaks rule ids. Result and path
  limits are configurable for callers that store findings in a database or
  render them in a bounded field. Scans report every occurrence with a fully
  masked preview by default. Use `occurrences: :first_per_file` to collapse a
  credential repeated in one file, or `preview: :redacted` to retain a short
  recognisable prefix and suffix.
  """

  alias SecretScan.Scanner

  @type finding :: %{
          rule: String.t(),
          file_path: String.t(),
          line: pos_integer(),
          byte_offset: non_neg_integer(),
          fingerprint: binary(),
          preview: String.t()
        }

  @type rule_selection :: :all | :hexpm | [String.t()]
  @type priority_rule_selection :: :all | :hexpm | :none | [String.t()]
  @type occurrence_mode :: :all | :first_per_file
  @type preview_mode :: :masked | :redacted

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

  @spec scan(Path.t(), [scan_option()]) :: {[finding()], boolean()}
  def scan(dir, opts \\ []), do: Scanner.scan_directory(dir, opts)
end
