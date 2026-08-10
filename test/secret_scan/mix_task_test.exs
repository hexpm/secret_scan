defmodule SecretScan.MixTaskTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  @github_token "ghp_" <> "016Cq2mKvXbNzR8dLpWyTuAeH3jFgS4iOU7Q"

  setup do
    root = Path.join(System.tmp_dir!(), "hex-secrets-task-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    {:ok, root: root}
  end

  test "scans files selected by project config", %{root: root} do
    write(root, "lib/app.ex", "defmodule App do\nend\n")

    output =
      in_project(root, [secret_scan: [files: ["lib"]]], fn ->
        capture_io(fn -> Mix.Tasks.SecretScan.run([]) end)
      end)

    assert output =~ "Scanning 1 files from the current project's secret_scan config"
    assert output =~ "No leaked credentials found"
  end

  test "fails CI and prints masked findings by default", %{root: root} do
    write(root, "config/runtime.exs", "token = \"#{@github_token}\"\n")

    output =
      capture_io(:stderr, fn ->
        assert_raise Mix.Error, "Found 1 leaked credentials", fn ->
          in_project(root, [secret_scan: [files: ["config"]]], fn ->
            Mix.Tasks.SecretScan.run([])
          end)
        end
      end)

    assert output =~ "config/runtime.exs:1 [github-pat] ************"
    refute output =~ @github_token
  end

  test "configures occurrence reporting and redacted previews", %{root: root} do
    write(
      root,
      "config/runtime.exs",
      String.duplicate("token = \"#{@github_token}\"\n", 2)
    )

    output =
      capture_io(:stderr, fn ->
        assert_raise Mix.Error, "Found 1 leaked credentials", fn ->
          in_project(
            root,
            [
              secret_scan: [
                files: ["config"],
                rules: ["github-pat"],
                occurrences: :first_per_file,
                preview: :redacted
              ]
            ],
            fn -> Mix.Tasks.SecretScan.run([]) end
          )
        end
      end)

    assert output =~ "config/runtime.exs:1 [github-pat] ghp_************OU7Q"
    refute output =~ "config/runtime.exs:2"
  end

  test "uses the configured Gitleaks rules", %{root: root} do
    write(root, "config/runtime.exs", "token = \"#{@github_token}\"\n")
    write(root, "config/keystore.p12", "not really a keystore")

    output =
      capture_io(:stderr, fn ->
        assert_raise Mix.Error, "Found 1 leaked credentials", fn ->
          in_project(
            root,
            [secret_scan: [files: ["config"], rules: ["github-pat"]]],
            fn -> Mix.Tasks.SecretScan.run([]) end
          )
        end
      end)

    assert output =~ "[github-pat]"
    refute output =~ "pkcs12-file"
  end

  test "scans Hex package files", %{root: root} do
    write(root, "lib/app.ex", "defmodule App do\nend\n")
    write(root, "test/fixtures/leak.env", "token = \"#{@github_token}\"\n")

    output =
      in_project(
        root,
        [
          package: [
            files: ["lib", "test/fixtures"],
            secret_scan: [ignore: ["test/fixtures/**"]]
          ]
        ],
        fn ->
          capture_io(fn -> Mix.Tasks.SecretScan.run([]) end)
        end
      )

    assert output =~ "Scanning 2 files from the current project's Hex package config"
    assert output =~ "No leaked credentials found"
  end

  defp in_project(root, config, fun) do
    config = [app: :secret_scan_fixture, version: "0.1.0"] ++ config

    Mix.Project.in_project(:secret_scan_fixture, root, config, fn _project ->
      Mix.Task.reenable("secret_scan")
      fun.()
    end)
  end

  defp write(root, path, content) do
    full = Path.join(root, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, content)
  end
end
