defmodule Mix.Tasks.SecretScan.RefreshTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.SecretScan.Refresh

  @source File.read!("rules/gitleaks.toml")
  @license File.read!("rules/LICENSE.gitleaks")
  @source_metadata File.read!("rules/SOURCE")

  test "downloads every source from the selected commit" do
    sha = String.duplicate("a", 40)

    assert %{config: config, license: license} = Refresh.source_urls(sha)
    assert config =~ "/#{sha}/config/gitleaks.toml"
    assert license =~ "/#{sha}/LICENSE"
    refute config =~ "/master/"
    refute license =~ "/master/"
  end

  test "authenticates the GitHub API request when a token is set" do
    assert Refresh.api_options("token") == [auth: {:bearer, "token"}]
    assert Refresh.api_options("") == []
    assert Refresh.api_options(nil) == []
  end

  test "records the selected commit" do
    sha = String.duplicate("a", 40)

    assert Refresh.source_metadata(sha, "2026-08-10T12:30:00Z") ==
             """
             repository: https://github.com/gitleaks/gitleaks
             commit: #{sha}
             date: 2026-08-10
             """
  end

  test "detects any outdated vendored source" do
    dir = temporary_dir()
    File.write!(Path.join(dir, "gitleaks.toml"), @source)
    File.write!(Path.join(dir, "LICENSE.gitleaks"), @license)
    File.write!(Path.join(dir, "SOURCE"), @source_metadata)

    refute Refresh.outdated?(dir, @source, @license, @source_metadata)
    assert Refresh.outdated?(dir, @source <> "\n", @license, @source_metadata)
    assert Refresh.outdated?(dir, @source, @license <> "\n", @source_metadata)
    assert Refresh.outdated?(dir, @source, @license, @source_metadata <> "\n")
  end

  test "validates every source before replacing either file" do
    dir = temporary_dir()
    File.write!(Path.join(dir, "gitleaks.toml"), "old config")
    File.write!(Path.join(dir, "LICENSE.gitleaks"), "old license")
    File.write!(Path.join(dir, "SOURCE"), "old source")

    invalid = String.replace(@source, ~s|minVersion = "v8.25.0"|, ~s|minVersion = "v9.0.0"|)

    assert_raise ArgumentError, ~r/unsupported gitleaks minVersion/, fn ->
      Refresh.install!(dir, invalid, @license, @source_metadata)
    end

    assert File.read!(Path.join(dir, "gitleaks.toml")) == "old config"
    assert File.read!(Path.join(dir, "LICENSE.gitleaks")) == "old license"
    assert File.read!(Path.join(dir, "SOURCE")) == "old source"
  end

  test "installs the validated config and license together" do
    dir = temporary_dir()
    File.write!(Path.join(dir, "gitleaks.toml"), "old config")
    File.write!(Path.join(dir, "LICENSE.gitleaks"), "old license")
    File.write!(Path.join(dir, "SOURCE"), "old source")

    assert :ok = Refresh.install!(dir, @source, @license, @source_metadata)
    assert File.read!(Path.join(dir, "gitleaks.toml")) == @source
    assert File.read!(Path.join(dir, "LICENSE.gitleaks")) == @license
    assert File.read!(Path.join(dir, "SOURCE")) == @source_metadata
  end

  test "leaves both targets unchanged when staging either file fails" do
    dir = temporary_dir()
    File.write!(Path.join(dir, "gitleaks.toml"), "old config")
    File.mkdir!(Path.join(dir, "LICENSE.gitleaks"))
    File.write!(Path.join(dir, "SOURCE"), "old source")

    assert_raise File.Error, fn ->
      Refresh.install!(dir, @source, @license, @source_metadata)
    end

    assert File.read!(Path.join(dir, "gitleaks.toml")) == "old config"
    assert File.dir?(Path.join(dir, "LICENSE.gitleaks"))
    assert File.read!(Path.join(dir, "SOURCE")) == "old source"
  end

  defp temporary_dir do
    dir =
      Path.join(System.tmp_dir!(), "secret-scan-refresh-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    dir
  end
end
