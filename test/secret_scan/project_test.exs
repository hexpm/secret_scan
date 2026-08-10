defmodule SecretScan.ProjectTest do
  use ExUnit.Case, async: true

  alias SecretScan.Project

  setup do
    root =
      Path.join(System.tmp_dir!(), "hex-secrets-project-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    {:ok, root: root}
  end

  test "uses file patterns from project config", %{root: root} do
    write(root, "lib/app.ex", "defmodule App do\nend\n")
    write(root, "config/runtime.exs", "import Config\n")
    write(root, "README.md", "docs\n")

    config = [
      secret_scan: [
        files: ["lib", "config/*.exs"],
        rules: :hexpm,
        priority_rules: :none,
        occurrences: :first_per_file,
        preview: :redacted,
        ignore: ["lib/generated/**"],
        max_concurrency: 2,
        max_findings: 50,
        max_locations: 5,
        max_path_length: 200
      ]
    ]

    assert {:ok, ["config/runtime.exs", "lib/app.ex"], opts, :project} =
             Project.resolve(config, root)

    assert opts[:ignore] == ["lib/generated/**"]
    assert opts[:rules] == :hexpm
    assert opts[:priority_rules] == :none
    assert opts[:occurrences] == :first_per_file
    assert opts[:preview] == :redacted
    assert opts[:max_concurrency] == 2
    assert opts[:max_findings] == 50
    assert opts[:max_locations] == 5
    assert opts[:max_path_length] == 200
  end

  test "uses Hex package files and merges its ignore globs", %{root: root} do
    write(root, "lib/app.ex", "defmodule App do\nend\n")
    write(root, "mix.exs", "# fixture\n")

    config = [package: [], secret_scan: [ignore: ["priv/generated/**"]]]

    config =
      Keyword.put(config, :package,
        files: ["lib/app.ex", "mix.exs"],
        secret_scan: [ignore: ["test/fixtures/**"]]
      )

    assert {:ok, ["lib/app.ex", "mix.exs"], opts, :package} =
             Project.resolve(config, root)

    assert opts[:ignore] == ["test/fixtures/**", "priv/generated/**"]
  end

  test "requires file config for a project without a package", %{root: root} do
    assert {:error, message} = Project.resolve([], root)
    assert message =~ "secret_scan: [files: [...]]"
  end

  test "rejects a project config that matches no files", %{root: root} do
    assert_raise Mix.Error, "secret_scan :files didn't match any regular files", fn ->
      Project.resolve([secret_scan: [files: ["missing"]]], root)
    end
  end

  test "rejects project files outside the project root", %{root: root} do
    parent_file =
      Path.join(Path.dirname(root), "outside-#{System.unique_integer([:positive])}.exs")

    File.write!(parent_file, "import Config\n")
    on_exit(fn -> File.rm!(parent_file) end)

    assert_raise Mix.Error, ~r/secret_scan :files must stay inside the project root/, fn ->
      Project.resolve([secret_scan: [files: ["../#{Path.basename(parent_file)}"]]], root)
    end
  end

  defp write(root, path, content) do
    full = Path.join(root, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, content)
  end
end
