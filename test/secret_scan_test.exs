defmodule SecretScanTest do
  use ExUnit.Case, async: true

  @github_token "ghp_" <> "016Cq2mKvXbNzR8dLpWyTuAeH3jFgS4iOU7Q"

  setup do
    dir = Path.join(System.tmp_dir!(), "secret-scan-api-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    {:ok, dir: dir}
  end

  test "scans a directory recursively", %{dir: dir} do
    write(dir, "lib/app.ex", "defmodule App do\nend\n")
    write(dir, ".env", "GITHUB_TOKEN=#{@github_token}\n")

    assert {[%{file_path: ".env", rule: "github-pat"} = finding], false} =
             SecretScan.scan(dir)

    refute finding.preview =~ @github_token
  end

  test "honors ignore globs", %{dir: dir} do
    write(dir, "config/runtime.exs", "GITHUB_TOKEN=#{@github_token}\n")
    write(dir, "fixtures/ignored.env", "GITHUB_TOKEN=#{@github_token}\n")

    assert {[%{file_path: "config/runtime.exs"}], false} =
             SecretScan.scan(dir, ignore: ["fixtures/**"])
  end

  test "does not descend into globally excluded directories", %{dir: dir} do
    write(dir, ".git/config", "GITHUB_TOKEN=#{@github_token}\n")

    assert {[], false} = SecretScan.scan(dir)
  end

  test "selects a named or explicit Gitleaks ruleset", %{dir: dir} do
    write(dir, ".env", "GITHUB_TOKEN=#{@github_token}\n")
    write(dir, "certs/keystore.p12", "not really a keystore")

    assert {[%{rule: "github-pat"}], false} = SecretScan.scan(dir, rules: :hexpm)

    assert {[%{rule: "pkcs12-file"}], false} =
             SecretScan.scan(dir, rules: ["pkcs12-file"])
  end

  test "configures occurrences and previews", %{dir: dir} do
    write(dir, ".env", String.duplicate("GITHUB_TOKEN=#{@github_token}\n", 2))

    assert {findings, false} = SecretScan.scan(dir, rules: ["github-pat"])

    assert Enum.map(findings, &{&1.line, &1.preview}) == [
             {1, "************"},
             {2, "************"}
           ]

    assert {[%{line: 1, preview: "ghp_************OU7Q"}], false} =
             SecretScan.scan(dir,
               rules: ["github-pat"],
               occurrences: :first_per_file,
               preview: :redacted
             )
  end

  test "rejects a missing directory" do
    missing = Path.join(System.tmp_dir!(), "missing-secret-scan-directory")

    assert_raise ArgumentError, ~r/secret scan directory does not exist/, fn ->
      SecretScan.scan(missing)
    end
  end

  test "includes directory traversal in the scan budget", %{dir: dir} do
    for n <- 1..1_000 do
      write(dir, "files/#{n}.txt", "safe\n")
    end

    assert {[], true} = SecretScan.scan(dir, scan_timeout: 1)
  end

  defp write(dir, path, content) do
    full = Path.join(dir, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, content)
  end
end
