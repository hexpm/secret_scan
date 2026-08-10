defmodule SecretScan.Scanner do
  @moduledoc false

  @doc """
  Runs the ruleset over files without loading whole files into memory.

  Files are streamed in overlapping windows, so peak memory is bounded by one
  window rather than one file.
  """

  require Logger

  alias SecretScan.Rules

  @chunk_size 262_144
  @carry_size 65_536
  @default_max_findings 100
  @default_max_locations 10
  @default_max_path_length :infinity
  @file_timeout 10_000
  @scan_timeout 30_000
  @line_context 4_096
  @preview_stars 12
  @inline_allow "gitleaks:allow"

  # The one catch-all in the ruleset. It fires alongside whichever specific
  # rule already caught the same value, so it loses when they collide.
  @catch_all_rule "generic-api-key"

  def scan_directory(dir, opts) do
    dir = Path.expand(dir)

    unless File.dir?(dir) do
      raise ArgumentError, "secret scan directory does not exist: #{dir}"
    end

    started_at = System.monotonic_time(:millisecond)
    opts = prepare_opts(opts)
    deadline = started_at + scan_timeout(opts)
    {file_paths, failures, halted} = directory_files(dir, opts, deadline)

    scan_files_prepared(dir, file_paths, opts, deadline, failures, halted)
  end

  defp directory_files(dir, opts, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {[], 0, :budget}
    else
      parent = self()
      ref = make_ref()

      {pid, monitor} =
        spawn_monitor(fn ->
          send(parent, {ref, walk_directory(dir, [""], [], 0, false, opts, deadline)})
        end)

      receive do
        {^ref, result} ->
          Process.demonitor(monitor, [:flush])
          result

        {:DOWN, ^monitor, :process, _pid, reason} ->
          Logger.warning("Secret scan could not enumerate #{dir}: #{inspect(reason)}")
          {[], 0, :crash}
      after
        remaining ->
          Process.exit(pid, :kill)
          Process.demonitor(monitor, [:flush])
          flush(ref)
          {[], 0, :budget}
      end
    end
  end

  defp walk_directory(_root, [], files, failures, halted, _opts, _deadline),
    do: {files, failures, halted}

  defp walk_directory(root, [relative | rest], files, failures, _halted, opts, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      {files, failures, :budget}
    else
      full = Path.join(root, relative)

      case File.ls(full) do
        {:ok, names} ->
          result =
            Enum.reduce_while(names, {:ok, files, rest, failures}, fn name,
                                                                      {:ok, files, directories,
                                                                       failures} ->
              if System.monotonic_time(:millisecond) >= deadline do
                {:halt, {:budget, files, failures}}
              else
                relative = Path.join(relative, name)
                full = Path.join(root, relative)

                case File.lstat(full) do
                  {:ok, %File.Stat{type: :regular}} ->
                    {:cont, {:ok, [relative | files], directories, failures}}

                  {:ok, %File.Stat{type: :directory}} ->
                    if excluded_directory?(relative, opts) do
                      {:cont, {:ok, files, directories, failures}}
                    else
                      {:cont, {:ok, files, [relative | directories], failures}}
                    end

                  {:ok, _stat} ->
                    {:cont, {:ok, files, directories, failures}}

                  {:error, reason} ->
                    Logger.warning(
                      "Secret scan could not inspect #{relative}: #{format_reason(reason)}"
                    )

                    {:cont, {:ok, files, directories, failures + 1}}
                end
              end
            end)

          case result do
            {:ok, files, directories, failures} ->
              walk_directory(root, directories, files, failures, false, opts, deadline)

            {:budget, files, failures} ->
              {files, failures, :budget}
          end

        {:error, reason} ->
          path = if relative == "", do: root, else: relative
          Logger.warning("Secret scan could not list #{path}: #{format_reason(reason)}")
          walk_directory(root, rest, files, failures + 1, false, opts, deadline)
      end
    end
  end

  @doc """
  Scans `file_paths`, relative to `dir`, and returns `{findings, incomplete?}`.

  Findings are capped at the configured `:max_findings`; `incomplete?` says
  whether anything was dropped or a file couldn't be scanned. Files are
  scanned concurrently because matching is CPU-bound, and a single file that
  defeats the keyword prefilter is abandoned after #{div(@file_timeout, 1000)}
  seconds rather than being allowed to consume the whole scan budget.

  Options include:

    * `:ignore` - file path globs to skip
    * `:rules` - `:all` (the default), `:hexpm`, or a list of Gitleaks rule ids
    * `:priority_rules` - rules retained first when `:max_findings` is reached;
      accepts `:all`, `:hexpm` (the default), `:none`, or rule ids
    * `:occurrences` - `:all` (the default) or `:first_per_file`
    * `:preview` - `:masked` (the default) or `:redacted`
    * `:fingerprint_key` - HMAC key for stable fingerprints. A random key is
      generated for each scan when omitted.
    * `:file_timeout` - per-file timeout in milliseconds
    * `:scan_timeout` - whole-scan timeout in milliseconds
    * `:max_concurrency` - maximum files scanned at once, defaults to the
      number of online schedulers
    * `:max_findings` - maximum findings returned, defaults to
      #{@default_max_findings}
    * `:max_locations` - maximum locations returned for one credential,
      defaults to #{@default_max_locations}
    * `:max_path_length` - maximum stored path length, defaults to `:infinity`
  """
  def scan_files(dir, file_paths, opts \\ []) do
    started_at = System.monotonic_time(:millisecond)
    opts = prepare_opts(opts)
    deadline = started_at + scan_timeout(opts)

    scan_files_prepared(Path.expand(dir), file_paths, opts, deadline, 0, false)
  end

  defp scan_files_prepared(dir, file_paths, opts, deadline, failures, halted) do
    state = scan_all(dir, file_paths, opts, deadline, failures, halted)

    log_incomplete(dir, state, opts)
    {findings, dropped_locations?} = finalize_findings(state.kept, opts)

    {cap(findings, max_findings(opts), priority_rules(opts)),
     state.halted != false or state.timeouts > 0 or state.failures > 0 or dropped_locations? or
       state.total > max_findings(opts) or length(findings) > max_findings(opts)}
  end

  # The stream is consumed in a process of its own so the budget is a deadline
  # rather than a suggestion. Reducing over it here would only let us read the
  # clock when a result arrived, so a file that stalled just before the deadline
  # took a whole file timeout more on top of it. It also contains a crash: the
  # tasks are linked to the collector, and `Task.async_stream` propagates a task
  # that raises or exits to whoever is consuming it, so run here that would take
  # the scan and its caller with it.
  defp scan_all(dir, file_paths, opts, deadline, failures, halted) do
    parent = self()
    ref = make_ref()

    {collector, monitor} =
      spawn_monitor(fn ->
        file_paths
        # Unordered so a file that runs to its timeout doesn't hold every result
        # behind it; nothing here cares what order they arrive in.
        |> Task.async_stream(&scan_file_raw(dir, &1, opts),
          max_concurrency: max_concurrency(opts),
          timeout: file_timeout(opts),
          on_timeout: :kill_task,
          ordered: false,
          zip_input_on_exit: true
        )
        |> Enum.each(&send(parent, {ref, &1}))

        send(parent, {ref, :done})
      end)

    state =
      collect(
        dir,
        ref,
        monitor,
        %{
          kept: [],
          total: 0,
          halted: halted,
          timeouts: 0,
          failures: failures,
          max_findings: max_findings(opts),
          priority_rules: priority_rules(opts)
        },
        deadline
      )

    # Killing the collector kills whatever it still had running.
    Process.exit(collector, :kill)
    Process.demonitor(monitor, [:flush])
    flush(ref)
    state
  end

  defp collect(dir, ref, monitor, state, deadline) do
    case deadline - System.monotonic_time(:millisecond) do
      remaining when remaining <= 0 ->
        %{state | halted: :budget}

      remaining ->
        receive do
          {^ref, :done} ->
            state

          {^ref, result} ->
            collect(dir, ref, monitor, accumulate(result, state), deadline)

          {:DOWN, ^monitor, :process, _pid, reason} ->
            Logger.warning("Secret scan of #{dir} crashed: #{inspect(reason)}")
            %{state | halted: :crash}
        after
          remaining -> %{state | halted: :budget}
        end
    end
  end

  defp flush(ref) do
    receive do
      {^ref, _result} -> flush(ref)
    after
      0 -> :ok
    end
  end

  # The accumulator is capped as it grows rather than at the end. A tree of
  # small files each holding thousands of matches would otherwise build the
  # whole list before the cap ever applied, using 3 GB of heap to report one finding.
  defp accumulate({:ok, {:ok, found}}, state) do
    %{
      state
      | kept: cap(state.kept ++ found, state.max_findings, state.priority_rules),
        total: state.total + length(found)
    }
  end

  defp accumulate({:ok, {:error, _reason}}, state) do
    %{state | failures: state.failures + 1}
  end

  # The only exit the stream yields. A task that raises or exits takes the
  # collector down instead, which `collect/5` sees as a monitor message.
  defp accumulate({:exit, {_path, :timeout}}, state) do
    %{state | timeouts: state.timeouts + 1}
  end

  defp file_timeout(opts), do: Keyword.get(opts, :file_timeout, @file_timeout)
  defp scan_timeout(opts), do: Keyword.get(opts, :scan_timeout, @scan_timeout)
  defp max_concurrency(opts), do: Keyword.fetch!(opts, :max_concurrency)
  defp max_findings(opts), do: Keyword.fetch!(opts, :max_findings)
  defp max_locations(opts), do: Keyword.fetch!(opts, :max_locations)
  defp max_path_length(opts), do: Keyword.fetch!(opts, :max_path_length)
  defp priority_rules(opts), do: Keyword.fetch!(opts, :resolved_priority_rules)

  # Once per scan rather than once per file: a tree built to be slow
  # times out on every file in it, and ninety identical lines say nothing the
  # count doesn't.
  defp log_incomplete(_dir, %{halted: false, timeouts: 0, failures: 0}, _opts), do: :ok

  # The crash already logged itself, with the reason.
  defp log_incomplete(_dir, %{halted: :crash}, _opts), do: :ok

  defp log_incomplete(dir, state, opts) do
    details =
      [
        if(state.failures > 0, do: "#{state.failures} files could not be scanned"),
        if(state.timeouts > 0, do: "#{state.timeouts} files timed out"),
        if(state.halted == :budget, do: "hit the #{scan_timeout(opts)}ms budget")
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(", ")

    Logger.warning("Secret scan of #{dir} incomplete: #{details}")
  end

  defp finalize_findings(findings, opts) do
    findings =
      findings
      |> Enum.sort_by(&{&1.file_path, &1.secret_offset, &1.rule == @catch_all_rule, &1.rule})
      # A specific rule and the catch-all can identify the same credential at
      # the same position. Report that occurrence once, under the specific rule.
      |> Enum.uniq_by(&{&1.fingerprint, &1.file_path, &1.secret_offset})
      |> Enum.sort_by(&{&1.file_path, &1.line, &1.secret_offset, &1.rule})
      |> select_occurrences(Keyword.fetch!(opts, :occurrences))
      |> Enum.sort_by(&{&1.file_path, &1.line, &1.byte_offset, &1.rule})

    {findings, dropped_locations?} = take_locations(findings, max_locations(opts))
    {Enum.map(findings, &Map.delete(&1, :secret_offset)), dropped_locations?}
  end

  defp select_occurrences(findings, :all), do: findings

  defp select_occurrences(findings, :first_per_file),
    do: Enum.uniq_by(findings, &{&1.fingerprint, &1.file_path})

  # Past the configured limit, the remedy is still to rotate the credential.
  # Dropping further locations marks the scan as incomplete.
  defp take_locations(findings, max_locations) do
    {kept, {_counts, dropped?}} =
      Enum.flat_map_reduce(findings, {%{}, false}, fn finding, {counts, dropped?} ->
        seen = Map.get(counts, finding.fingerprint, 0)
        counts = Map.put(counts, finding.fingerprint, seen + 1)

        if seen < max_locations do
          {[finding], {counts, dropped?}}
        else
          {[], {counts, true}}
        end
      end)

    {kept, dropped?}
  end

  defp cap(findings, max_findings, _priority_rules) when length(findings) <= max_findings,
    do: findings

  defp cap(findings, max_findings, priority_rules) do
    {priority, remaining} = Enum.split_with(findings, &priority_rule?(&1.rule, priority_rules))
    priority = fair_take(priority, max_findings)
    remaining_limit = max_findings - length(priority)
    {catch_all, specific} = Enum.split_with(remaining, &(&1.rule == @catch_all_rule))
    specific = fair_take(specific, remaining_limit)
    remaining_limit = remaining_limit - length(specific)

    priority ++
      specific ++
      (catch_all
       |> Enum.sort_by(&finding_order/1)
       |> Enum.take(remaining_limit))
  end

  defp priority_rule?(_rule, :all), do: true
  defp priority_rule?(_rule, :none), do: false
  defp priority_rule?(rule, rules), do: MapSet.member?(rules, rule)

  # One noisy rule cannot consume the whole report before another rule gets a
  # slot. Take one finding from each rule in stable order, then a second from
  # each, leaving the catch-all until every specific rule has competed.
  defp fair_take(findings, limit) do
    groups =
      findings
      |> Enum.group_by(& &1.rule)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {_rule, findings} -> Enum.sort_by(findings, &finding_order/1) end)

    fair_take_round(groups, limit, [])
  end

  defp fair_take_round(_groups, 0, findings), do: findings
  defp fair_take_round([], _limit, findings), do: findings

  defp fair_take_round(groups, limit, findings) do
    {round, remaining_groups} =
      Enum.reduce(groups, {[], []}, fn
        [finding], {round, remaining} ->
          {[finding | round], remaining}

        [finding | rest], {round, remaining} ->
          {[finding | round], [rest | remaining]}
      end)

    round = Enum.reverse(round)
    selected = Enum.take(round, limit)
    findings = findings ++ selected

    if length(selected) < length(round) do
      findings
    else
      fair_take_round(Enum.reverse(remaining_groups), limit - length(selected), findings)
    end
  end

  defp finding_order(finding) do
    {finding.file_path, Map.get(finding, :secret_offset, finding.byte_offset), finding.rule}
  end

  defp collapse_raw_occurrences(findings, :all), do: findings

  defp collapse_raw_occurrences(findings, :first_per_file) do
    findings
    |> Enum.sort_by(fn finding ->
      {finding.file_path, finding.secret_offset, finding.rule == @catch_all_rule, finding.rule}
    end)
    |> Enum.uniq_by(&{&1.fingerprint, &1.file_path})
  end

  @doc """
  Scans one file, relative to `dir`.

  Accepts the same options as `scan_files/3`.
  """
  def scan_file(dir, path, opts \\ []) do
    opts = prepare_opts(opts)

    {findings, _dropped_locations?} =
      case scan_file_raw(Path.expand(dir), path, opts) do
        {:ok, findings} -> findings
        {:error, _reason} -> []
      end
      |> finalize_findings(opts)

    findings
  end

  defp scan_file_raw(dir, path, opts) do
    with {:ok, relative} <- Path.safe_relative(path, dir),
         full = Path.join(dir, relative),
         {:ok, %File.Stat{type: :regular}} <- File.lstat(full) do
      {:ok, scan(path, fn -> stream_windows(full) end, opts)}
    else
      :error ->
        Logger.warning(
          "Secret scan could not read #{path}: not a relative path inside the scan root"
        )

        {:error, :outside_scan_root}

      {:ok, _stat} ->
        Logger.warning("Secret scan could not read #{path}: not a regular file")
        {:error, :not_regular}

      {:error, reason} ->
        Logger.warning("Secret scan could not read #{path}: #{format_reason(reason)}")
        {:error, reason}
    end
  rescue
    # One unreadable file is not the scan. A task raising here takes the
    # collector in `scan_all/6` with it, which costs every other file still
    # running and whatever was still queued behind them.
    exception ->
      Logger.warning("Secret scan could not read #{path}: #{Exception.message(exception)}")
      {:error, exception}
  end

  @doc """
  Scans content already in memory, under the name `path`.

  Same windowing as reading from disk, so a caller holding the bytes already,
  such as a corpus scan unpacking tarballs straight to memory, gets the same answer
  without a round trip through the filesystem.
  """
  def scan_content(path, content, opts \\ []) do
    opts = prepare_opts(opts)

    {findings, _dropped_locations?} =
      path
      |> scan(fn -> binary_windows(content) end, opts)
      |> finalize_findings(opts)

    findings
  end

  defp scan(path, windows, opts) do
    rules = Keyword.fetch!(opts, :resolved_rules)
    ignore = Keyword.get(opts, :ignore, [])

    if Rules.allowed_path?(path) or ignored?(path, ignore) do
      []
    else
      content_rules = Rules.for_path(path, rules)

      # A file of one repeated credential yields a match every twenty bytes,
      # so retain a bounded set while scanning every window.
      {findings, _state} =
        Enum.reduce(windows.(), {[], MapSet.new()}, fn window, {found, seen} ->
          {new, seen} =
            scan_window(window, path, content_rules, forget_passed(seen, window), opts)

          # Keep one over the cap so the caller knows the result is incomplete.
          # Continue through the file so a specific credential after a run of
          # catch-all matches can replace one of them in the bounded list.
          found = collapse_raw_occurrences(found ++ new, Keyword.fetch!(opts, :occurrences))
          {cap(found, max_findings(opts) + 1, priority_rules(opts)), seen}
        end)

      path_findings(path, rules, opts) ++ findings
    end
  end

  defp prepare_opts(opts) do
    if opts[:__secret_scan_prepared__] do
      opts
    else
      opts
      |> put_ignore()
      |> put_fingerprint_key()
      |> Keyword.put(:resolved_rules, Rules.resolve!(Keyword.get(opts, :rules, :all)))
      |> Keyword.put(
        :resolved_priority_rules,
        Rules.resolve_priority!(Keyword.get(opts, :priority_rules, :hexpm))
      )
      |> put_choice(:occurrences, :all, [:all, :first_per_file])
      |> put_choice(:preview, :masked, [:masked, :redacted])
      |> put_positive_limit(:file_timeout, @file_timeout)
      |> put_positive_limit(:scan_timeout, @scan_timeout)
      |> put_positive_limit(:max_concurrency, System.schedulers_online())
      |> put_positive_limit(:max_findings, @default_max_findings)
      |> put_positive_limit(:max_locations, @default_max_locations)
      |> put_path_length()
      |> Keyword.put(:__secret_scan_prepared__, true)
    end
  end

  defp put_ignore(opts) do
    case Keyword.get(opts, :ignore, []) do
      globs when is_list(globs) ->
        case Enum.find(globs, &(not is_binary(&1))) do
          nil -> Keyword.put(opts, :ignore, compile_globs(globs))
          glob -> raise ArgumentError, ":ignore entries must be strings, got: #{inspect(glob)}"
        end

      globs ->
        raise ArgumentError, ":ignore must be a list of strings, got: #{inspect(globs)}"
    end
  end

  defp put_fingerprint_key(opts) do
    case Keyword.fetch(opts, :fingerprint_key) do
      :error -> Keyword.put(opts, :fingerprint_key, :crypto.strong_rand_bytes(32))
      {:ok, key} when is_binary(key) -> opts
      {:ok, key} -> raise ArgumentError, ":fingerprint_key must be a binary, got: #{inspect(key)}"
    end
  end

  defp put_choice(opts, key, default, choices) do
    value = Keyword.get(opts, key, default)

    if value in choices do
      Keyword.put(opts, key, value)
    else
      expected = Enum.map_join(choices, " or ", &inspect/1)
      raise ArgumentError, ":#{key} must be #{expected}, got: #{inspect(value)}"
    end
  end

  defp put_positive_limit(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> Keyword.put(opts, key, value)
      value -> raise ArgumentError, ":#{key} must be a positive integer, got: #{inspect(value)}"
    end
  end

  defp put_path_length(opts) do
    case Keyword.get(opts, :max_path_length, @default_max_path_length) do
      :infinity ->
        Keyword.put(opts, :max_path_length, :infinity)

      value when is_integer(value) and value > 0 ->
        Keyword.put(opts, :max_path_length, value)

      value ->
        raise ArgumentError,
              ":max_path_length must be :infinity or a positive integer, got: #{inspect(value)}"
    end
  end

  defp format_reason(reason), do: reason |> :file.format_error() |> IO.iodata_to_binary()

  # `seen` exists to stop the overlap between two windows reporting the same
  # match twice, so it only has to remember the part of the file the next window
  # will read again. Every match puts a key in it whether or not it survives the
  # entropy floor and the allowlists, and only survivors count towards the cap
  # that stops the file, so without this a file of dense low-entropy matches
  # grows the set with the file rather than with the answer. The set is bounded
  # by the matches in one window, the same order as the list `Regex.scan/3`
  # builds for a single rule.
  defp forget_passed(seen, {_content, offset, _first?, _last?, _newlines}) do
    MapSet.filter(seen, fn {_rule, position} -> position >= offset end)
  end

  # A path the caller asked us to skip. `patterns` are already-compiled regexes
  # (see `compile_globs/1`).
  defp ignored?(_path, []), do: false

  defp ignored?(path, patterns), do: Enum.any?(patterns, &Regex.match?(&1, path))

  defp excluded_directory?(path, opts) do
    patterns = Keyword.fetch!(opts, :ignore)

    globally_excluded? =
      Path.extname(Path.basename(path)) == "" and Rules.allowed_path?(path)

    globally_excluded? or ignored?(path, patterns) or ignored?(path <> "/", patterns)
  end

  # `**` spans directory separators, `*` stays within a segment, `?` is one
  # non-separator character. A malformed glob is dropped rather than crashing
  # the scan. `a/**/b` matches `a/b` as well as `a/x/b`, and `**/b` matches a
  # `b` at the root, the way shells and gitignore read them.
  defp compile_globs(globs), do: Enum.flat_map(globs, &compile_glob/1)

  defp compile_glob(glob) when is_binary(glob) do
    pattern =
      glob
      |> String.split(~r{(\A\*\*/|/\*\*/|\*\*|\*|\?)}, include_captures: true, trim: true)
      |> Enum.map_join(fn
        "**/" -> "(?:.*/)?"
        "/**/" -> "(?:/.*/|/)"
        "**" -> ".*"
        "*" -> "[^/]*"
        "?" -> "[^/]"
        literal -> Regex.escape(literal)
      end)

    case Regex.compile("\\A" <> pattern <> "\\z") do
      {:ok, regex} -> [regex]
      _ -> []
    end
  end

  defp compile_glob(_glob), do: []

  # Rules that fire on the filename alone, like a checked-in .p12 keystore.
  defp path_findings(path, rules, opts) do
    for rule <- Rules.path_rules(rules), Regex.match?(rule.path, path) do
      %{
        rule: rule.id,
        file_path: stored_path(path, opts),
        line: 1,
        byte_offset: 0,
        secret_offset: 0,
        # Domain separated: a path finding and a content finding whose secret
        # happens to be that path must not collapse into one another through
        # the fingerprint they are deduped on.
        fingerprint: fingerprint("path:" <> path, opts),
        preview: printable(Path.basename(path))
      }
    end
  end

  @doc false
  # Emits `{content, offset, first?, last?, newlines_before}` windows, each the
  # last #{@carry_size} bytes of the previous window followed by the next chunk.
  # `last?` comes from the total size rather than from waiting to see the
  # stream end, so no window has to be held back to discover it is the final
  # one.
  def stream_windows(absolute_path) do
    absolute_path
    |> File.stream!(@chunk_size)
    |> windows(File.stat!(absolute_path).size)
  end

  @doc false
  def binary_windows(content) do
    size = byte_size(content)

    0..max(size - 1, 0)//@chunk_size
    |> Stream.map(&binary_part(content, &1, min(@chunk_size, size - &1)))
    |> windows(size)
  end

  defp windows(chunks, size) do
    Stream.transform(chunks, {<<>>, 0, 0, true}, fn chunk, {carry, offset, newlines, first?} ->
      window = carry <> chunk
      window_size = byte_size(window)
      last? = offset + window_size >= size
      keep = if last?, do: 0, else: min(@carry_size, window_size)
      consumed = window_size - keep

      next = {
        :binary.copy(binary_part(window, consumed, keep)),
        offset + consumed,
        newlines + count_newlines(binary_part(window, 0, consumed)),
        false
      }

      {[{window, offset, first?, last?, newlines}], next}
    end)
  end

  defp scan_window({content, offset, first?, last?, newlines_before}, path, rules, seen, opts) do
    rules
    |> Rules.candidates(content)
    |> Enum.flat_map_reduce(seen, fn rule, seen ->
      rule
      |> matches(content, first?, last?)
      # A window of one repeated credential yields a match every twenty bytes,
      # and the caller's cap only applies between windows, so the window has to
      # stop itself. Counting findings rather than matches: most matches die in
      # the entropy floor or an allowlist, and capping the raw matches would
      # hold the survivors well under the limit.
      |> Enum.reduce_while({[], seen}, fn match, {found, seen} ->
        key = {rule.id, offset + match.start}

        {found, seen} =
          if MapSet.member?(seen, key) do
            {found, seen}
          else
            finding = finding(rule, match, content, path, offset, newlines_before, opts)

            {add_finding(found, finding, Keyword.fetch!(opts, :occurrences)),
             MapSet.put(seen, key)}
          end

        # One over the cap, so a window producing exactly the cap stays
        # distinguishable from one that overflowed it.
        if length(found) > max_findings(opts) do
          {:halt, {found, seen}}
        else
          {:cont, {found, seen}}
        end
      end)
    end)
  end

  defp add_finding(found, nil, _occurrences), do: found
  defp add_finding(found, finding, :all), do: found ++ [finding]

  defp add_finding(found, finding, :first_per_file) do
    if Enum.any?(found, &(&1.fingerprint == finding.fingerprint)) do
      found
    else
      found ++ [finding]
    end
  end

  # A match touching a window edge is left to the neighbouring window, which
  # sees it with real context. 152 of the rules end in an alternation with `$`,
  # and `$` matches the end of the window, so a secret sliced by a chunk
  # boundary would otherwise match against the cut. Symmetrically `\b` fires at
  # the first byte of a window where mid-file it would not.
  #
  # Since windows overlap by the carry, any match shorter than that is interior
  # to one of them and is found exactly once. Longer matches depend on where
  # they land. One longer than a whole window is missed, which affects the handful
  # of rules with unbounded quantifiers can produce those, `private-key` being
  # the realistic one, and a 4096-bit key is three kilobytes.
  defp matches(rule, content, first?, last?) do
    size = byte_size(content)

    rule.regex
    |> Regex.scan(content, return: :index)
    |> Enum.flat_map(fn groups ->
      {start, length} = hd(groups)

      cond do
        not first? and start == 0 -> []
        not last? and start + length == size -> []
        true -> [%{start: start, length: length, secret: secret_span(groups, rule.secret_group)}]
      end
    end)
  end

  # gitleaks takes the first NON-EMPTY capture group when a rule sets no
  # `secretGroup`, and keeps the whole match when every group is empty. Taking
  # group 1 unconditionally silently drops every rule written as a top-level
  # alternation with one group per branch. `atlassian-api-token` never fired
  # on a modern ATATT3 token, and that rule sends email.
  defp secret_span([whole | groups], nil) do
    Enum.find(groups, whole, fn {start, length} -> start >= 0 and length > 0 end)
  end

  defp secret_span([whole | _] = groups, index) do
    case Enum.at(groups, index) do
      {start, length} when start >= 0 and length > 0 -> {start, length}
      _ -> whole
    end
  end

  defp finding(rule, match, content, path, offset, newlines_before, opts) do
    {secret_start, secret_length} = match.secret
    secret = :binary.copy(binary_part(content, secret_start, secret_length))
    whole = :binary.copy(binary_part(content, match.start, match.length))

    targets = %{
      path: path,
      secret: secret,
      match: whole,
      line: line_text(content, match)
    }

    with false <- annotated_allowed?(targets.line),
         true <- entropy_ok?(rule, secret),
         false <- Rules.allowed?(rule.allowlists, targets),
         false <- Rules.allowed?(Rules.global_allowlists(), targets) do
      %{
        rule: rule.id,
        file_path: stored_path(path, opts),
        line: newlines_before + count_newlines(binary_part(content, 0, match.start)) + 1,
        byte_offset: offset + match.start,
        secret_offset: offset + secret_start,
        fingerprint: fingerprint(secret, opts),
        preview: preview(secret, opts)
      }
    else
      _ -> nil
    end
  end

  defp fingerprint(value, opts),
    do: :crypto.mac(:hmac, :sha256, Keyword.fetch!(opts, :fingerprint_key), value)

  # gitleaks honours an inline `gitleaks:allow` on the line, which is how a
  # project marks a deliberate fixture. A package that vendors an annotated
  # test file should not earn its owner a security email.
  defp annotated_allowed?(line), do: String.contains?(line, @inline_allow)

  defp entropy_ok?(%{entropy: nil}, _secret), do: true
  # Exclusive, as in gitleaks: `if entropy <= r.Entropy { continue }`.
  defp entropy_ok?(%{entropy: floor}, secret), do: Rules.entropy(secret) > floor

  # Bounded on both sides: a minified bundle is one line and we are not putting
  # a megabyte of it through a regex.
  defp line_text(content, match) do
    before_start = max(match.start - @line_context, 0)
    after_end = min(match.start + match.length + @line_context, byte_size(content))

    from =
      case :binary.matches(binary_part(content, before_start, match.start - before_start), "\n") do
        [] -> before_start
        matches -> before_start + elem(List.last(matches), 0) + 1
      end

    tail_start = match.start + match.length

    to =
      case :binary.match(binary_part(content, tail_start, after_end - tail_start), "\n") do
        :nomatch -> after_end
        {position, _length} -> tail_start + position
      end

    :binary.copy(binary_part(content, from, to - from))
  end

  defp count_newlines(binary), do: length(:binary.matches(binary, "\n"))

  @doc """
  Masks a secret for display, keeping enough of it to be recognisable.

  The raw value isn't returned, only this and an HMAC fingerprint. The
  mask is a fixed width rather than the secret's length, so a matched PEM block
  doesn't become a three kilobyte row of asterisks.
  """
  def redact(secret) do
    size = byte_size(secret)
    # Never show more than a sixth from each end. The finding also carries an
    # HMAC of the value, so on a ten character secret the old fixed
    # four-and-four left two unknown characters and the hash to check them
    # against, which is not redaction.
    keep = if size < 12, do: 0, else: min(4, div(size, 6))

    if keep == 0 do
      String.duplicate("*", min(size, @preview_stars))
    else
      printable(binary_part(secret, 0, keep)) <>
        String.duplicate("*", @preview_stars) <>
        printable(binary_part(secret, size - keep, keep))
    end
  end

  defp preview(secret, opts) do
    case Keyword.fetch!(opts, :preview) do
      :redacted -> redact(secret)
      :masked -> String.duplicate("*", min(byte_size(secret), @preview_stars))
    end
  end

  # Rules run over binary files and paths come from tar entry names, so both a
  # match and a file name can hold bytes that are not text. They land in a
  # Postgres text column, which rejects a NUL outright, and in a plain text
  # email, where an escape sequence lets a publisher write their own paragraph
  # into mail that arrives from hex.pm.
  defp printable(binary) do
    binary
    |> String.replace_invalid()
    |> String.replace(~r/[[:cntrl:]]/u, "�")
  end

  defp stored_path(path, opts) do
    path = printable(path)

    case max_path_length(opts) do
      :infinity -> path
      max_path_length -> String.slice(path, 0, max_path_length)
    end
  end
end
