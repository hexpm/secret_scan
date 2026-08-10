defmodule SecretScan.ScannerLimitsTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias SecretScan.Scanner

  setup do
    dir = Path.join(System.tmp_dir!(), "secret-scan-limits-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    {:ok, dir: dir}
  end

  test "a file built to defeat the prefilter is abandoned, not scanned", %{dir: dir} do
    # Four vendor rules cost ~210 ms/KB on keyword-dense input, a thousand
    # times the rest. A 32 KB file of them gzips to 85 bytes, so a tarball
    # well under the publish limit holds thousands. Budgets are shrunk here
    # rather than spending the real thirty seconds.
    slow = String.duplicate("meraki", 2730) <> String.duplicate("a", 16382)
    paths = for n <- 1..40, do: write_path(dir, "slow_#{n}.txt", slow)

    log =
      capture_log(fn ->
        assert {[], true} =
                 Scanner.scan_files(dir, paths,
                   rules: :all,
                   file_timeout: 50,
                   scan_timeout: 200
                 )
      end)

    assert log =~ "incomplete"
  end

  test "the release budget is a ceiling, not a suggestion", %{dir: dir} do
    # Every slot busy with a file that outlasts the budget, and a file timeout
    # far past it. Reading the clock only when a result arrives would sit here
    # for as long as the slowest file takes rather than stopping at 300 ms.
    slow = String.duplicate("meraki", 2730) <> String.duplicate("a", 16382)

    paths =
      for n <- 1..(System.schedulers_online() * 2), do: write_path(dir, "slow_#{n}.txt", slow)

    {elapsed, _log} =
      :timer.tc(fn ->
        capture_log(fn ->
          assert {[], true} =
                   Scanner.scan_files(dir, paths,
                     rules: :all,
                     file_timeout: 60_000,
                     scan_timeout: 300
                   )
        end)
      end)

    assert div(elapsed, 1000) < 2_000
  end

  defp write(dir, path, contents) do
    full = Path.join(dir, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, contents)
  end

  defp write_path(dir, path, contents) do
    write(dir, path, contents)
    path
  end
end
