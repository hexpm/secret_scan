defmodule SecretScan.RuleSourceTest do
  use ExUnit.Case, async: true

  alias SecretScan.RuleSource

  @source File.read!("rules/gitleaks.toml")

  test "accepts the vendored Gitleaks schema" do
    assert %{"rules" => [_ | _]} = RuleSource.decode!(@source)
  end

  test "rejects a ruleset that requires unsupported semantics" do
    source = String.replace(@source, ~s|minVersion = "v8.25.0"|, ~s|minVersion = "v9.0.0"|)

    assert_raise ArgumentError, ~r/unsupported gitleaks minVersion/, fn ->
      RuleSource.decode!(source)
    end
  end

  test "rejects unknown fields instead of silently ignoring them" do
    source =
      String.replace(
        @source,
        ~s|title = "gitleaks config"|,
        "title = \"gitleaks config\"\nnewFeature = true"
      )

    assert_raise ArgumentError, "unsupported fields in config: newFeature", fn ->
      RuleSource.decode!(source)
    end
  end

  test "rejects empty keyword patterns before installation" do
    source = Regex.replace(~r/keywords = \[[^\]]+\]/, @source, ~s|keywords = [""]|, global: false)

    assert_raise ArgumentError, ~r/keywords .* invalid value/, fn ->
      RuleSource.decode!(source)
    end
  end
end
