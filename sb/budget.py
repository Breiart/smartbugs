import math, os, datetime, time
import sb.analysis, sb.logging, sb.colors, sb.smartbugs, sb.cfg, sb.io

def _read_all_tools_alias():
    """Return the list of tool base names declared in tools/all/config.yaml.

    Falls back to an empty list if the alias file cannot be read.
    """
    try:
        fn = os.path.join(sb.cfg.TOOLS_HOME, "all", sb.cfg.TOOL_CONFIG)
        data = sb.io.read_yaml(fn)
        alias = data.get("alias", [])
        if isinstance(alias, list):
            return [str(x) for x in alias]
        return []
    except Exception:
        return []


def _collect_completed_keys(files, settings):
    """Collect completed tool|args keys per contract from result artifacts.

    Looks for smartbugs.json files under the default results folder and filters
    entries for the current run id. Returns a mapping {absfn: {"tool|args", …}}.
    """
    completed = {}
    # Build relfn -> absfn mapping from provided files list
    rel_to_abs = {rel: abs for (abs, rel) in files}
    runid = getattr(settings, "runid", None)
    results_root = "results"
    if not runid or not os.path.isdir(results_root):
        return completed

    for root, _dirs, files_ in os.walk(results_root):
        if f"{os.path.sep}{runid}{os.path.sep}" not in (root + os.path.sep):
            continue
        for name in files_:
            if name != sb.cfg.TASK_LOG:
                continue
            fn = os.path.join(root, name)
            try:
                data = sb.io.read_json(fn)
                relfn = data.get("filename")
                tool = (data.get("tool") or {}).get("id", "")
                tool_args = (data.get("tool_args") or "").strip()
                base = tool.split("-")[0]
                key = f"{base}|{tool_args}"
                absfn = rel_to_abs.get(relfn)
                if absfn:
                    completed.setdefault(absfn, set()).add(key)
            except Exception:
                # ignore unreadable entries
                pass

    return completed

def _existing_keys_for_file(settings, absfn):
    key_map = getattr(settings, "tool_keys", {})
    if isinstance(key_map, set):
        # Normalize older shapes into a dict keyed by absfn
        key_map = {absfn: key_map}
        settings.tool_keys = key_map
    elif not isinstance(key_map, dict):
        key_map = {}
        settings.tool_keys = key_map
    return set(key_map.get(absfn, set()))


def plan_budget_tasks(files, settings, remaining_seconds):
    """
    Plan follow-up tasks sized to use the remaining wall-clock budget.

    Strategy:
    - Consider only Solidity files for now.
            #TODO Incorpoorate compatibility with .hex and .rt
    - For each file, compute the set of tools that have not yet run (based on
      in-memory scheduling keys and existing artifacts) using the 'all' alias
      order, excluding 'sfuzz' which is used as a final fallback per file.
    - Schedule tasks in a round-robin across files, one tool at a time, until
      the estimated worker-seconds of planned tasks meets or slightly exceeds
      remaining_seconds * processes.
    - Per-task timeouts use a fair base slice derived from the remaining time
      and number of files, optionally capped by per-tool numeric TIMEOUTS.
    """

    remaining = int(max(0, remaining_seconds))
    if remaining <= 0:
        return []

    # Build the list of all available tools from the 'all' alias
    all_tools = _read_all_tools_alias()
    if not all_tools:
        sb.logging.message("No tool alias list found; skipping second-phase planning.", "INFO")
        return []

    # For completeness checks, exclude sFuzz: reaching full coverage then triggers sFuzz
    coverage_tools = [t for t in all_tools if t.lower() != "sfuzz"]

    # Consider only Solidity files for now
    files_by_abs = {absfn: relfn for (absfn, relfn) in files if absfn.endswith(".sol")}
    if not files_by_abs:
        sb.logging.message("No Solidity files eligible for the second phase.", "INFO")
        return []

    contracts = list(files_by_abs.items())
    contracts_count = len(contracts)
    if contracts_count <= 0:
        return []

    # Resolve configurables
    try:
        target_fraction = float(getattr(sb.cfg, "BUDGET_TARGET_FRACTION", 0.8))
    except Exception:
        target_fraction = 0.8
    try:
        min_timeout = int(getattr(sb.cfg, "BUDGET_MIN_TIMEOUT", 10))
    except Exception:
        min_timeout = 10

    # Incorporate any already completed tool keys from artifacts to avoid duplicates
    completed_keys = _collect_completed_keys(files, settings)
    for absfn, keys in completed_keys.items():
        key_map = getattr(settings, "tool_keys", {})
        if isinstance(key_map, set):
            key_map = {absfn: key_map}
            settings.tool_keys = key_map
        elif not isinstance(key_map, dict):
            key_map = {}
            settings.tool_keys = key_map
        existing = key_map.setdefault(absfn, set())
        existing.update(keys)

    # Build missing tools per file (preserving alias order)
    missing_per_file = {}
    for absfn, relfn in contracts:
        existing = _existing_keys_for_file(settings, absfn)
        used_bases = {k.split("|")[0] for k in existing}
        missing = [t for t in coverage_tools if t not in used_bases]
        existing_list = ", ".join(sorted(existing)) if existing else "none"
        missing_list = ", ".join(missing) if missing else "none"
        sb.logging.message(
            f"[budget] {os.path.basename(absfn)} -> ran: {existing_list}; missing: {missing_list}",
            "INFO",
        )
        missing_per_file[absfn] = missing

    # Count potential tasks available to size per-task timeout. This includes
    # all missing tools and, at most once per file, sFuzz as a fallback.
    potential_tasks = 0
    for absfn, _relfn in contracts:
        existing = _existing_keys_for_file(settings, absfn)
        used_bases = {k.split("|")[0] for k in existing}
        potential_tasks += len(missing_per_file.get(absfn, []))
        if "sfuzz" not in used_bases:
            potential_tasks += 1

    processes = max(1, int(getattr(settings, "processes", 1)))
    # Target total worker-seconds to plan so wall-clock ≈ remaining * target_fraction
    target_worker_seconds = int(remaining * processes * target_fraction)
    # Base per-task timeout aiming to fill the target with available tasks
    per_task_base = max(min_timeout, int(math.ceil(target_worker_seconds / max(1, potential_tasks))))

    # Plan tasks round-robin across files until we saturate the target
    planned = []
    planned_worker_seconds = 0

    # Next index to schedule from each file's missing list
    next_idx = {absfn: 0 for absfn in files_by_abs}
    files_cycle = list(files_by_abs.keys())

    def schedule(absfn, relfn, tool_name):
        nonlocal planned_worker_seconds
        # Compute effective timeout: take per-tool minimum if configured, otherwise base slice.
        tool_min = sb.cfg.TIMEOUTS.get(tool_name)
        if not isinstance(tool_min, (int, float)):
            tool_min = 0
        eff_timeout = max(min_timeout, int(per_task_base), int(tool_min))
        # Clamp each task timeout to the time remaining for this batch planning call
        eff_timeout = min(eff_timeout, remaining)
        new_task = sb.smartbugs.collect_single_task(absfn, relfn, tool_name, settings, tool_args="", timeout=eff_timeout)
        if new_task:
            planned.append(new_task)
            planned_worker_seconds += eff_timeout
            sb.logging.message(
                f"[budget] {os.path.basename(absfn)} -> schedule {tool_name} (timeout: {eff_timeout}s)",
                "INFO",
            )
            return True
        return False

    progress = True
    while planned_worker_seconds < target_worker_seconds and progress:
        progress = False
        for absfn in files_cycle:
            relfn = files_by_abs[absfn]
            idx = next_idx[absfn]
            missing = missing_per_file.get(absfn, [])
            if idx < len(missing):
                if schedule(absfn, relfn, missing[idx]):
                    next_idx[absfn] = idx + 1
                    progress = True
            elif "sfuzz" not in {k.split("|")[0] for k in _existing_keys_for_file(settings, absfn)}:
                # Fallback: schedule sFuzz once per file if not yet used
                if schedule(absfn, relfn, "sfuzz"):
                    # Mark as done to avoid repeated attempts
                    next_idx[absfn] = idx + 1
                    progress = True

            if planned_worker_seconds >= target_worker_seconds:
                break

    # Log a brief summary
    est_wall = int(math.ceil(planned_worker_seconds / max(1, processes)))
    sb.logging.message(
        f"[budget] Planned {len(planned)} task(s) for ~{est_wall}s wall-clock (target ~{int(remaining * target_fraction)}s of {remaining}s).",
        "INFO",
    )

    return planned


def run_budget_phase(files, settings, remaining_seconds, total_start=None):
    """Run follow-up tasks while time remains, striving to use the budget.

    Plans tasks sized to the remaining time and runs them. If the work finishes
    earlier than expected (tools often complete before hitting their timeout),
    plans another batch and continues until the budget is exhausted or no more
    tasks are available.
    """

    remaining = int(max(0, remaining_seconds))
    if remaining <= 0:
        sb.logging.message("[budget] No remaining time for second phase.", "INFO")
        return 0

    # Temporarily disable dynamic scheduling for predictability in budget phase
    prev_dynamic = getattr(settings, "dynamic", True)
    settings.dynamic = False
    total_elapsed = 0
    batch_no = 1
    try:
        while True:
            time_left = max(0, remaining - total_elapsed)
            if time_left <= 0:
                break

            tasks = plan_budget_tasks(files, settings, time_left)
            if not tasks:
                if batch_no == 1:
                    sb.logging.message("[budget] No tasks planned for second phase.", "INFO")
                else:
                    sb.logging.message("[budget] No further tasks to schedule within remaining time.", "INFO")
                break

            sb.logging.message(sb.colors.success(
                f"[budget] Running batch #{batch_no} with {len(tasks)} task(s), time left ~{time_left}s."))

            # Footer to print overall total at the end of this run, if total_start is provided
            extra = None
            if total_start is not None:
                def footer():
                    total = datetime.timedelta(seconds=round(time.time() - total_start))
                    return f"Analysis completed in {total}."
                extra = footer

            start = time.time()
            sb.analysis.run(tasks, settings, label=f"Second phase (batch {batch_no})", extra_messages=[extra] if extra else None)
            batch_elapsed = int(time.time() - start)
            total_elapsed += batch_elapsed
            sb.logging.message(
                f"[budget] Batch #{batch_no} finished in ~{batch_elapsed}s. Remaining budget: ~{max(0, remaining - total_elapsed)}s.",
                "INFO",
            )

            # If tasks finished much earlier than the planned time, iterate again
            batch_no += 1

        return total_elapsed
    finally:
        settings.dynamic = prev_dynamic
