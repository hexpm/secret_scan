# SecretScan

[![CI](https://github.com/hexpm/secret_scan/actions/workflows/ci.yml/badge.svg)](https://github.com/hexpm/secret_scan/actions/workflows/ci.yml)

SecretScan detects credentials in project directories. Its rules are vendored
from [gitleaks](https://github.com/gitleaks/gitleaks), and scanning is
implemented in Elixir so it can run as a library in the BEAM.

## Installation

Add `secret_scan` as a dependency in the environment where CI runs it:

```elixir
def deps do
  [
    {:secret_scan, "~> 0.1", only: [:dev, :test], runtime: false}
  ]
end
```

## CI task

Run the scanner from the project directory:

```sh
mix secret_scan
```

When the current project defines a Hex package, the task scans the same regular
files selected for `mix hex.build`. It reads ignore globs from that project's
package metadata:

```elixir
defp package do
  [
    files: ~w(lib priv mix.exs README.md),
    secret_scan: [ignore: ["test/fixtures/**", "priv/certs/*.pem"]]
  ]
end
```

A project that doesn't define a Hex package selects files from its own
top-level project config:

```elixir
def project do
  [
    app: :my_app,
    version: "0.1.0",
    secret_scan: [
      files: ["lib", "config", "priv"],
      rules: :hexpm,
      occurrences: :all,
      preview: :masked,
      ignore: ["test/fixtures/**"]
    ]
  ]
end
```

The task returns a non-zero status when it finds a credential or can't complete
the scan within its resource limits.

## Library

`SecretScan.scan/2` recursively scans a directory:

```elixir
{findings, incomplete?} =
  SecretScan.scan(File.cwd!(),
    rules: :hexpm,
    ignore: ["test/fixtures/**"]
  )
```

Findings include a rule id, file location, masked or redacted preview, and HMAC
fingerprint. The matching credential isn't returned.

Pass `fingerprint_key: key` when fingerprints must be stable across scans. The
default is a new random key for each call, which supports deduplication within
that result without producing a persistent candidate-checking hash.

The scanner runs every vendored Gitleaks rule by default. Pass `rules: :hexpm`
to use the subset Hex.pm uses for package-owner notifications, or select rule
ids directly:

```elixir
SecretScan.scan(File.cwd!(),
  rules: ["github-pat", "aws-access-token", "slack-bot-token"]
)
```

Unknown ids raise instead of silently disabling a CI check. The same `:rules`
option works in the top-level `:secret_scan` project config used by
`mix secret_scan`.

When `:max_findings` is reached, `priority_rules: :hexpm` retains findings from
the high-precision Hex.pm ruleset first. This is the default. Pass `:none`,
`:all`, or a list of rule ids to change that priority without changing which
rules are scanned.

The operational limits are configurable in both APIs:

```elixir
SecretScan.scan(File.cwd!(),
  file_timeout: 10_000,
  scan_timeout: 30_000,
  max_concurrency: System.schedulers_online(),
  priority_rules: :hexpm,
  occurrences: :all,
  preview: :masked,
  max_findings: 100,
  max_locations: 10,
  max_path_length: :infinity
)
```

`:occurrences` can be `:all` or `:first_per_file`. The latter reports the first
location of a credential in each file while still reporting that credential in
other files. `:preview` can be `:masked`, which shows no credential bytes, or
`:redacted`, which retains a short prefix and suffix.

`:max_locations` limits how many locations are reported for the same
credential. The result's `incomplete?` flag is true when a file can't be read,
a timeout expires, or either finding limit drops results. Paths are sanitized
for display and aren't shortened unless `:max_path_length` is set.

## Rules

`rules/gitleaks.toml` is vendored from Gitleaks'
`config/gitleaks.toml`. `rules/SOURCE` records the upstream commit and date.
The config and its upstream MIT license are included in the package.

When working in the SecretScan source checkout, run `mix secret_scan.refresh`
to fetch the latest ruleset. Pass `--check-outdated` to exit with status 100
when the vendored files differ. A nightly GitHub Actions workflow uses this to
open or update a pull request.

The task resolves the current upstream commit, downloads the config and license
from that commit, and validates the supported schema and every regex before
replacing the vendored files. It performs one mechanical rewrite: literal
example credentials in upstream allowlists have their final byte wrapped in a
character class. The regex remains equivalent, while repository secret scanners
no longer see a contiguous credential.

The regexes target Go's RE2 syntax. They don't use lookaround or backreferences,
so Erlang's PCRE engine can compile them. A keyword prefilter limits how many
patterns run against each content window.
