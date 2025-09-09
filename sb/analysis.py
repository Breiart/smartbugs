import multiprocessing, time, datetime, os, subprocess, signal, sys
import sb.logging, sb.colors, sb.docker, sb.cfg, sb.io, sb.parsing, sb.sarif, sb.errors
import sb.smartbugs, sb.vulnerability

CORE_TOOLS = (
    ("slither", ""),
    ("smartcheck", ""),
    ("mythril", ""),
    ("solhint", ""),
    ("maian", ""),
    ("confuzzius", ""),
)

def task_log_dict(task, start_time, duration, exit_code, log, output, docker_args):
    return {
        "filename": task.relfn,
        "runid": task.settings.runid,
        "result": {
            "start": start_time,
            "duration": duration,
            "exit_code": exit_code,
            "logs": sb.cfg.TOOL_LOG if log else None,
            "output": sb.cfg.TOOL_OUTPUT if output else None},
        "solc": str(task.solc_version) if task.solc_version else None,
        "tool": task.tool.dict(),
        "tool_args": task.tool_args,
        "docker": docker_args,
        "platform": sb.cfg.PLATFORM,
    }


def call_reparse(results_directory):
    try:
        result = subprocess.run(
            ["python3", "-m", "sb.reparse", results_directory],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        if result.stderr:
            sb.logging.message(f"DEBUG Reparse stderr:\n{result.stderr}", "DEBUG")
    except subprocess.CalledProcessError as e:
        sb.logging.message(f"[ERROR] Reparse failed: {e.stderr}", "ERROR")
        return None

    parsed_path = os.path.join(results_directory, sb.cfg.PARSER_OUTPUT)
    if os.path.exists(parsed_path):
        return sb.io.read_json(parsed_path)

    sb.logging.message("Parsed output not found after reparse.", "ERROR")
    return None


def analyze_parsed_results(parsed_output):
    """
    Analyze parsed output and extract a list of detected vulnerability types.
    Returns:
        list: List of detected vulnerability types, e.g. ["REENTRANCY", "SUICIDAL"]
    """
    if parsed_output is None:
        return []
    
    tool_id = parsed_output.get("parser", {}).get("id")
    
    analyzer = sb.vulnerability.VulnerabilityAnalyzer()
    vuln_list = analyzer.analyze(tool_id, parsed_output)

    return vuln_list


def route_next_tool(vuln_list, task_settings=None, scheduled_tools=None, absfn=None):
    """ Determine additional tools to run based on detected vulnerabilities.
    Multiple findings may map to the same tool with different arguments. In
    such cases the arguments are merged so that a tool is scheduled only once
    with the union of all requested options. Duplicate argument sets are
    ignored and a previous run without arguments prevents any further runs of
    that tool when ``skip_after_no_args`` is enabled.

    Returns:
        list[tuple]: A list of tuples ``(tool_name, tool_args, timeout)`` where
        ``timeout`` may be ``None`` if no custom timeout is requested.
    """

    if not vuln_list:
        return []
    
    # Mapping from vulnerability categories to follow-up tools and optional timeouts
    VULN_TOOL_MAP = {
        # Reentrancy-related
        "REENTRANCY": ("mythril", "--modules ExternalCalls", "normal"),
        "LOW_LEVEL_CALL": ("conkas", "-vt reentrancy", None),
        "UNLOCKED_ETHER": ("slither", "--detect reentrancy-eth, reentrancy-events, reentrancy-no-eth", None),
        #"REENTRANCY_NO_GUARD": ("slither", "--reentrancy-no-guard", None),

        # Transaction order / front-running
        #"TOD": ("slither", "--detect out-of-order-retryable", None),
        "FRONT_RUNNING": ("slither", "--detect out-of-order-retryable", None),

        # Access control and kill paths
        "SUICIDAL": ("maian", "-c 0", None),
        "PRODIGAL": ("maian", "-c 1", None),
        "GREEDY_CONTRACT": ("maian", "-c 2", None),
        "GREEDY_CONTRACT": ("manticore", "--thorough-mode", None),
        "ARBITRARY_SEND": ("slither", "--detect arbitrary-send-erc20, arbitrary-send-erc20-permit, arbitrary-send-eth", None),

        # Arithmetic
        "OVERFLOW": ("mythril", "--modules IntegerArithmetics", None),
        "OVERFLOW": ("conkas", "-vt arithmetic", None),
        "OVERFLOW": ("osiris", "", None),
        #"OVERFLOW": ("ethor", "", None),
        
        "UNDERFLOW": ("mythril", "--modules IntegerArithmetics", None),
        "UNDERFLOW": ("conkas", "-vt arithmetic", None),
        "UNDERFLOW": ("osiris", "", None),
        #"UNDERFLOW": ("ethor", "", None),

        # Visibility / authorization
        "UNINITIALIZED_STORAGE_POINTER": ("slither", "--detect uninitialized-storage", None),
        "UNINITIALIZED_STORAGE": ("slither", "--detect uninitialized-state", None),
        
        # Misc patterns
        "LOW_LEVEL_CALL": ("slither", "--detect low-level-calls", None),
        "LOW_LEVEL_CALL": ("conkas", "-vt unchecked_ll_calls", None),

        "DELEGATECALL": ("mythril", "--modules ArbitraryDelegateCall", None),
        "SELFDESTRUCT": ("maian", "-c 0", None),
        "ASSERT_VIOLATION": ("mythril", "--modules Exceptions", None),
        "WRITE_TO_ARBITRARY_STORAGE": ("mythril", "--modules ArbitraryStorage", None),
        "BLOCK_DEPENDENCE": ("slither", "--detect timestamp", None),

        "BLOCK_DEPENDENCE": ("conkas", "-vt time_manipulation", None),
        "WEAK_RANDOMNESS": ("slither", "--detect weak-prng", None),
        "VARIABLE_SHADOWING": ("slither", "--detect shadowing-state", None),
        "DEPRECATED_FUNCTION": ("slither", "--detect deprecated-standards", None),
        "UNUSED_STATE_VARIABLE": ("slither", "--detect unused-state", None),
        "STRICT_BALANCE_EQUALITY": ("mythril", "--modules UnexpectedEther", None),
        #"MISSING_INPUT_VALIDATION": ("smartcheck", "", None),
        
        "ARBITRARY_JUMP": ("manticore", "--policy icount", None),
        "DOS_GAS_LIMIT": ("securify", "", None),

        # Information disclosure
        "LEAK": ("slither", "--detect uninitialized-storage", None),

        # Versioning & other
        "OUTDATED_COMPILER": ("slither", "--detect solc-version", None),
        "VERSION_PRAGMA": ("slither", "--detect solc-version", None),

    }

    # Map base tool names to their requested argument sets and timeouts
    tool_args_map = {}
    tool_timeout_map = {}

    existing_tool_keys = set()
    scheduled_tool_keys = set()
    skip_after_no_args = False

    if task_settings and absfn is not None:
        key_map = getattr(task_settings, "tool_keys", {})
        if isinstance(key_map, set):
            key_map = {absfn: key_map}
            task_settings.tool_keys = key_map
        elif not isinstance(key_map, dict):
            key_map = {}
            task_settings.tool_keys = key_map
        existing_tool_keys = key_map.get(absfn, set())
        skip_after_no_args = getattr(task_settings, "skip_after_no_args", False)

    if scheduled_tools is not None and absfn is not None:
        if isinstance(scheduled_tools, list):
            scheduled_tool_keys = set(scheduled_tools)
        else:
            try:
                scheduled_tool_keys = set(scheduled_tools.get(absfn, []))
            except Exception:
                # Manager likely unavailable during shutdown
                scheduled_tool_keys = set()
    
    # Collection of the requested argument sets in tool_args_map
    for vuln in vuln_list:
        for category in vuln.get("categories", []):
            tool_entry = VULN_TOOL_MAP.get(category)
            if not tool_entry:
                sb.logging.message(f"No route for category {category}", "DEBUG")
                continue
            
            base_name = tool_entry[0].split("-")[0]
            args = tool_entry[1].strip()
            timeout_id = tool_entry[2]
            entry_timeout = (
                sb.cfg.FOLLOWUP_TIMEOUTS.get(timeout_id) if timeout_id else None
            )
            base_key = f"{base_name}|"
            tool_key = f"{base_name}|{args}"

            if skip_after_no_args and (base_key in existing_tool_keys or base_key in scheduled_tool_keys):
                continue
            
            if tool_key in existing_tool_keys or tool_key in scheduled_tool_keys:
                continue
            
            arg_set = tool_args_map.setdefault(base_name, set())
            if args:
                arg_set.add(args)
            else:
                # A no-argument run overrides any flagged variants
                arg_set.clear()
            
            if entry_timeout is not None:
                prev = tool_timeout_map.get(base_name)
                if prev is None or entry_timeout > prev:
                    tool_timeout_map[base_name] = entry_timeout
        
        # Elaboration of the collected sets to create tool args
        scheduled = []
        for base_name, args_set in tool_args_map.items():
            timeout = tool_timeout_map.get(base_name)
            # If a tool has no args, schedule it with just its base name
            if not args_set:    
                scheduled.append((base_name, "", timeout))
                continue
            
            # Otherwise, group its args into a single command
            flag_groups = {}
            for arg in sorted(args_set):
                if " " in arg:
                    prefix, value = arg.split(" ", 1)
                else:
                    prefix, value = arg, ""
                flag_groups.setdefault(prefix, []).append(value)

            combined_parts = []
            for prefix, values in flag_groups.items():
                if values and values[0]:
                    combined_parts.append(f"{prefix} {','.join(values)}")
                else:
                    combined_parts.append(prefix)

            combined_args = " ".join(combined_parts)
            scheduled.append((base_name, combined_args, timeout))

    sb.logging.message(f"Routing to tools: {scheduled}", "DEBUG")

    return scheduled


def execute(task):    
    # create result dir if it doesn't exist
    if not os.path.exists(task.rdir):
        os.makedirs(task.rdir, exist_ok=True)
        if not os.path.isdir(task.rdir):
            raise sb.errors.SmartBugsError(f"Cannot create result directory {task.rdir}")
     
    # === Smart early exit ===
    fn_task_log = os.path.join(task.rdir, sb.cfg.TASK_LOG)
    if os.path.exists(fn_task_log):
        try:
            previous = sb.io.read_json(fn_task_log)
            if (not task.settings.overwrite
                and previous["tool"]["id"] == task.tool.id
                and previous["filename"] == task.relfn
                and previous.get("tool_args", "") == task.tool_args
            ):
                sb.logging.message(f"Skipping {task.tool.id} on {task.relfn} (already completed)", "INFO")
                return 0.0
        except Exception:
            pass  # fallback to running the tool

    # === Cleanup old results ===
    fn_task_log = os.path.join(task.rdir, sb.cfg.TASK_LOG)
    fn_tool_log = os.path.join(task.rdir, sb.cfg.TOOL_LOG)
    fn_tool_output = os.path.join(task.rdir, sb.cfg.TOOL_OUTPUT)
    fn_parser_output = os.path.join(task.rdir, sb.cfg.PARSER_OUTPUT)
    fn_sarif_output = os.path.join(task.rdir, sb.cfg.SARIF_OUTPUT)
    for fn in (fn_task_log, fn_tool_log, fn_tool_output, fn_parser_output, fn_sarif_output):
        try:
            os.remove(fn)
        except Exception:
            pass
        if os.path.exists(fn):
            raise sb.errors.SmartBugsError(f"Cannot clear old output {fn}")

    # Docker causes spurious connection errors
    # Therefore try each tool 3 times before giving up
    base_tool = task.tool.id.split("-")[0]
    executed = False
    tool_duration = 0.0
    tool_log = tool_output = docker_args = None
    # Do not override task or settings timeouts here; use configured values
    for attempt in range(3):
        
        now = time.localtime()
        now_str = str(now.tm_hour).zfill(2) + ":" + str(now.tm_min).zfill(2) + ":" + str(now.tm_sec).zfill(2)

        args_message = f"args: {task.tool_args}" if task.tool_args.strip() else "no args"
        sb.logging.message(f"\033[93mAttempt {attempt+1} of running {base_tool} with {args_message}. Current time: {now_str}\033[0m", "INFO")
        try:
            start_time = time.time()                    
            exit_code,tool_log,tool_output,docker_args = sb.docker.execute(task)                    
            duration = time.time() - start_time
            tool_duration += duration
            executed = True

            sb.logging.message(f"{base_tool} executed in: {tool_duration} seconds with exit code {exit_code}", "INFO")
            break       
        
        except sb.errors.SmartBugsError as e:
            sb.logging.message(sb.colors.error(f"Error while running {base_tool}: {e}"), "ERROR")
            if attempt == 2:
                raise                   
            sleep_duration = 15
            sb.logging.message(f"\033[93mSleeping for {sleep_duration} seconds before retry...\033[0m", "INFO")
            time.sleep(sleep_duration)    

    if executed:
        # Check whether result dir is empty,
        # and if not, whether we are going to overwrite it
        if os.path.exists(fn_task_log):
            old = sb.io.read_json(fn_task_log)
            old_fn = old["filename"]
            old_toolid = old["tool"]["id"]
            old_mode = old["tool"]["mode"]
            old_args = old.get("tool_args", "")
            if (task.relfn != old_fn 
                or task.tool.id != old_toolid 
                or task.tool.mode != old_mode 
                or task.tool_args != old_args
            ):
                raise sb.errors.SmartBugsError(f"Result directory {task.rdir} occupied by another task: ({old_toolid}/{old_mode}, {old_fn})")

        # write result to files
        task_log = task_log_dict(task, start_time, duration, exit_code, tool_log, tool_output, docker_args)
        if tool_log:
            sb.io.write_txt(fn_tool_log, tool_log)
        if tool_output:
            sb.io.write_bin(fn_tool_output, tool_output)

        # Write fn_task_log, to indicate that this task is done
        sb.io.write_json(fn_task_log, task_log)
            
        # Parse output of tool
        # If parsing fails, run the reparse script; no need to redo the analysis
        if task.settings.json or task.settings.sarif:
            parsed_result = sb.parsing.parse(task_log, tool_log, tool_output)
            sb.io.write_json(fn_parser_output,parsed_result)

            # Format parsed result as sarif
            if task.settings.sarif:
                sarif_result = sb.sarif.sarify(task_log["tool"], parsed_result["findings"])
                sb.io.write_json(fn_sarif_output, sarif_result)

    return tool_duration



def analyser(logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed, scheduled_tools, stop_event):
    # In worker processes, ignore Ctrl+C and TERM; the parent coordinates shutdown
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    except Exception:
        pass
        
    def pre_analysis():
        with tasks_started.get_lock():
            tasks_started_value = tasks_started.value + 1
            tasks_started.value = tasks_started_value
        args_str = task.tool_args.strip()
        args_info = f" with args {args_str}" if args_str else " with no args"
        sb.logging.message(
            f"Starting task {tasks_started_value}/{tasks_total.value}: {sb.colors.tool(task.tool.id)}{args_info} and {sb.colors.file(task.relfn)}",
            "", logqueue)

    def post_analysis(duration, no_processes, timeout):
        with tasks_completed.get_lock(), time_completed.get_lock():
            tasks_completed_value = tasks_completed.value + 1
            tasks_completed.value = tasks_completed_value
            time_completed_value = time_completed.value + duration
            time_completed.value = time_completed_value
        # estimated time to completion evaluated as time_so_far / completed_tasks * remaining_tasks / no_processes
        completed_tasks = tasks_completed_value
        time_so_far = time_completed_value
        with tasks_total.get_lock(), tasks_completed.get_lock():
            remaining_tasks = tasks_total.value - tasks_completed_value
        if timeout:
            # Assume that the first round of processes all ran into a timeout
            sb.logging.message(f"\033[95mConsidering timeout for ETC calculation\033[0m", "INFO")
            completed_tasks += no_processes
            time_so_far += timeout*no_processes
        etc = time_completed_value / completed_tasks * remaining_tasks / no_processes
        etc_fmt = datetime.timedelta(seconds=round(etc))
        sb.logging.message(f"{tasks_completed_value}/{tasks_total.value} completed, ETC {etc_fmt}")

    while True:
        task = taskqueue.get()
        if task is None:
            # Acknowledge the sentinel
            taskqueue.task_done()
            return
        sb.logging.quiet = task.settings.quiet
        pre_analysis()
        try:
            duration = 0.0
            run_duration = execute(task)
            duration += run_duration

            # Skip dynamic scheduling if we're shutting down
            if stop_event.is_set():
                args_str = task.tool_args.strip()
                args_info = f" with args {args_str}" if args_str else ""
                sb.logging.message(f"[{task.tool.id}{args_info}] executed in {run_duration}.", "INFO")
            elif task.settings.dynamic:
                # Call reparse after tool execution
                tool_parsed_output = call_reparse(task.rdir)

                # Analyze the parsed results and select next tool
                vuln_list = analyze_parsed_results(tool_parsed_output)
                next_tools = route_next_tool(vuln_list, task.settings, scheduled_tools, task.absfn)

                # Prevent dynamic task duplication
                new_tool_added = False
                key_map = getattr(task.settings, "tool_keys", {})
                if isinstance(key_map, set):
                    key_map = {task.absfn: key_map}
                    task.settings.tool_keys = key_map
                elif not isinstance(key_map, dict):
                    key_map = {}
                    task.settings.tool_keys = key_map
                existing_tool_keys = key_map.setdefault(task.absfn, set())
                skip_after_no_args = getattr(task.settings, "skip_after_no_args", False)
                for tool_name, tool_args, timeout in next_tools:
                    base_name = tool_name.split("-")[0]
                    tool_key = f"{base_name}|{tool_args.strip()}"
                    try:
                        scheduled_keys_for_file = scheduled_tools.get(task.absfn, [])
                    except Exception:
                        # Manager likely went away during shutdown
                        scheduled_keys_for_file = []
                    if skip_after_no_args and (f"{base_name}|" in existing_tool_keys or f"{base_name}|" in scheduled_keys_for_file):
                        sb.logging.message(f"Routing of {base_name} skipped: previous more complete execution already performed", "DEBUG")
                        continue
                    if tool_key in existing_tool_keys or tool_key in scheduled_keys_for_file:
                        continue

                    new_task = sb.smartbugs.collect_single_task(
                        task.absfn, task.relfn, tool_name, task.settings, tool_args, timeout
                    )
                    if new_task:
                        taskqueue.put(new_task)
                        scheduled_keys_for_file.append(tool_key)
                        try:
                            if isinstance(scheduled_tools, list):
                                scheduled_tools.append(tool_key)
                            else:
                                scheduled_tools[task.absfn] = scheduled_keys_for_file
                        except Exception:
                            # Manager might be down; skip recording
                            pass
                        existing_tool_keys.add(tool_key)
                        new_tool_added = True
                        with tasks_total.get_lock():
                            tasks_total.value += 1

                args_str = task.tool_args.strip()
                args_info = f" with args {args_str}" if args_str else ""
                added_info = ', '.join(f"{t[0]}|{t[1]}" for t in next_tools) if next_tools else 'no tool'
                sb.logging.message(f"[{task.tool.id}{args_info}] executed in {run_duration}, and added {added_info}.", "INFO")
            else:
                args_str = task.tool_args.strip()
                args_info = f" with args {args_str}" if args_str else ""
                sb.logging.message(f"[{task.tool.id}{args_info}] executed in {run_duration}.", "INFO")
 
        except sb.errors.SmartBugsError as e:
            duration = 0.0
            sb.logging.message(sb.colors.error(f"While analyzing {task.absfn} with {task.tool.id}:\n{e}"), "", logqueue)
        
        finally:
            # If shutting down, skip any Manager interactions to avoid races
            if stop_event.is_set():
                try:
                    taskqueue.task_done()
                except Exception:
                    pass
                post_analysis(duration, task.settings.processes, task.settings.timeout)
                return
            # Ensure core tools are scheduled at least once per contract
            key_map = getattr(task.settings, "tool_keys", {})
            if isinstance(key_map, set):
                key_map = {task.absfn: key_map}
                task.settings.tool_keys = key_map
            elif not isinstance(key_map, dict):
                key_map = {}
                task.settings.tool_keys = key_map

            scheduled_base_tools = set()
            key_set = key_map.get(task.absfn, set())
            scheduled_base_tools.update(k.split("|")[0] for k in key_set)

            try:
                file_sched = scheduled_tools.get(task.absfn, [])
            except Exception:
                file_sched = []
            scheduled_base_tools.update(k.split("|")[0] for k in file_sched)

            if task.settings.dynamic:
                missing_core_tools = [pair for pair in CORE_TOOLS if pair[0] not in scheduled_base_tools]
                
                if not new_tool_added and missing_core_tools:
                    next_tool, next_args = missing_core_tools[0]
                    core_tool_key = f"{next_tool}|{next_args.strip()}"
                    try:
                        scheduled_keys_for_file = scheduled_tools.get(task.absfn, [])
                    except Exception:
                        scheduled_keys_for_file = []
                    if core_tool_key in scheduled_keys_for_file:
                        continue                   
                    
                    new_task = sb.smartbugs.collect_single_task(task.absfn, task.relfn, next_tool, task.settings, next_args)
                    if new_task:
                        sb.logging.message(f"CORE TOOL ROUTE: SCHEDULING {next_tool}","DEBUG",)
                        taskqueue.put(new_task)
                        scheduled_keys_for_file.append(core_tool_key)
                        try:
                            if isinstance(scheduled_tools, list):
                                scheduled_tools.append(core_tool_key)
                            else:
                                scheduled_tools[task.absfn] = scheduled_keys_for_file
                        except Exception:
                            pass
                        with tasks_total.get_lock():
                            tasks_total.value += 1
                            existing_tool_keys.add(core_tool_key)
            
            # Always mark task as complete
            taskqueue.task_done()
        
        

        post_analysis(duration, task.settings.processes, task.settings.timeout)



def run(tasks, settings):
    # spawn processes (instead of forking), for identical behavior on Linux and MacOS
    mp = multiprocessing.get_context("spawn")

    # start shared logging
    logqueue = mp.Queue()
    sb.logging.start(settings.log, settings.overwrite, logqueue)
    try:
        start_time = time.time()
        
        # Interrupt coordination
        stop_event = mp.Event()
        last_signal = {"value": None}

        def _handle_signal(signum, _frame):
            # Avoid printing inside signal handler to prevent interleaving with shell prompt
            last_signal["value"] = signum
            stop_event.set()

        # Register handlers for Ctrl+C and TERM (e.g., gtimeout)
        try:
            signal.signal(signal.SIGINT, _handle_signal)
            signal.signal(signal.SIGTERM, _handle_signal)
        except Exception:
            # Some platforms/process models may not support installing handlers here
            pass

        # fill task queue using a joinable queue to wait for all tasks
        taskqueue = mp.JoinableQueue()

        for task in tasks:
            taskqueue.put(task)
 
        # accounting
        tasks_total = mp.Value('L', len(tasks))
        tasks_started = mp.Value('L', 0)
        tasks_completed = mp.Value('L', 0)
        time_completed = mp.Value('f', 0.0)

        # Use a multiprocessing.Manager for shared dict of scheduled tools per file
        manager = mp.Manager()
        scheduled_tools = manager.dict()


        # start analysers
        shared = (logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed, scheduled_tools, stop_event)
        analysers = [ mp.Process(target=analyser, args=shared) for _ in range(settings.processes) ]
        
        for a in analysers:
            a.start()

        # Wait for tasks to complete or for an interrupt
        while True:
            if stop_event.is_set():
                break
            # Check completion without blocking on JoinableQueue.join()
            with tasks_completed.get_lock():
                done = tasks_completed.value
            with tasks_total.get_lock():
                total = tasks_total.value
            if done >= total:
                break
            time.sleep(0.2)
        if stop_event.is_set():
            _msg = "Interrupt received — stopping analysers."
            if last_signal["value"] is not None:
                _msg = f"Signal {last_signal['value']} received — stopping analysers."
            sb.logging.message(sb.colors.warning(_msg), "", logqueue)
            # Best-effort: stop any running containers from this run
            try:
                sb.docker.cleanup_containers(getattr(settings, "runid", None))
            except Exception:
                pass
        else:
            sb.logging.message("All tasks finished or accounted for.", "DEBUG", logqueue)
        
        # now shut down workers
        for _ in range(settings.processes):
            taskqueue.put(None)
        # wait for analysers to finish (briefly), then force terminate if needed
        for a in analysers:
            a.join(timeout=5)
        for a in analysers:
            if a.is_alive():
                try:
                    a.terminate()
                except Exception:
                    pass
        for a in analysers:
            try:
                a.join(timeout=2)
            except Exception:
                pass

        # Final cleanup attempt after workers exit
        if stop_event.is_set():
            try:
                sb.docker.cleanup_containers(getattr(settings, "runid", None))
            except Exception:
                pass

        # good bye
        duration = datetime.timedelta(seconds=round(time.time()-start_time))
        if stop_event.is_set():
            sb.logging.message(f"Analysis interrupted after {duration}.", "", logqueue)
        else:
            sb.logging.message(f"Analysis completed in {duration}.", "", logqueue)
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        # Give the terminal a brief moment to render before the prompt returns
        time.sleep(0.1)

    finally:
        sb.logging.stop(logqueue)

    # If we were interrupted, exit with a conventional status code
    if stop_event.is_set():
        exit_code = 1
        try:
            if last_signal["value"] == signal.SIGINT:
                exit_code = 130  # 128 + SIGINT
            elif last_signal["value"] == signal.SIGTERM:
                exit_code = 143  # 128 + SIGTERM
        except Exception:
            pass
        sys.exit(exit_code)
