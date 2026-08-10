defmodule SecretScan.ScannerTimeoutTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias SecretScan.Scanner

  @github_token "ghp_" <> "016Cq2mKvXbNzR8dLpWyTuAeH3jFgS4iOU7Q"

  setup do
    dir = Path.join(System.tmp_dir!(), "secret-scan-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    on_exit(fn -> File.rm_rf!(dir) end)

    {:ok, dir: dir}
  end

  test "a file that outruns its budget doesn't take the ones beside it", %{dir: dir} do
    # Keyword-dense, so the prefilter skips nothing and every rule runs: a
    # megabyte of it takes over a second against the 100 ms budget below.
    write(
      dir,
      "slow.txt",
      String.duplicate(~s|okta = "sumo meraki api key secret auth"\n|, 25_000)
    )

    write(dir, ".env", "GITHUB_TOKEN=#{@github_token}\n")

    log =
      capture_log(fn ->
        assert {[finding], true} =
                 Scanner.scan_files(dir, ["slow.txt", ".env"],
                   rules: :all,
                   file_timeout: 100
                 )

        assert finding.file_path == ".env"
      end)

    assert log =~ "1 files timed out"
  end

  test "the release budget stops the scan and marks it incomplete", %{dir: dir} do
    write(
      dir,
      "slow.txt",
      String.duplicate(~s|okta = "sumo meraki api key secret auth"\n|, 25_000)
    )

    log =
      capture_log(fn ->
        assert {[], true} =
                 Scanner.scan_files(dir, ["slow.txt"], rules: :all, scan_timeout: 1)
      end)

    assert log =~ "incomplete"
    assert log =~ "budget"
  end

  defp write(dir, path, content) do
    full = Path.join(dir, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, content)
  end
end
