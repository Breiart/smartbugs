import multiprocessing, time, datetime, os, subprocess
import sb.logging, sb.colors, sb.docker, sb.cfg, sb.io, sb.parsing, sb.sarif, sb.errors
import sb.smartbugs, sb.vulnerability

#FIXME Placeholder in attesa di una logica migliore
CORE_TOOLS = {"slither", "mythril", "smartcheck", "manticore", "maian", "confuzzius"}

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


def route_next_tool(vuln_list, task_settings=None, scheduled_tools=None):
    """ Determine additional tools to run based on detected vulnerabilities.

        Multiple findings may map to the same tool with different arguments.  In
        such cases the arguments are merged so that a tool is scheduled only once
        with the union of all requested options.  Duplicate argument sets are
        ignored and a previous run without arguments prevents any further runs of
        that tool when 'skip_after_no_args' is enabled.
    """

    if not vuln_list:
        return []
    
    VULN_TOOL_MAP = {
        # Reentrancy-related
        "REENTRANCY": ("mythril", "--modules ExternalCalls"),
        "UNLOCKED_ETHER": ("slither", "--detect reentrancy-eth, reentrancy-events, reentrancy-no-eth"),
        #"REENTRANCY_NO_GUARD": ("slither", "--reentrancy-no-guard"),

        # Transaction order / front-running
        #"TOD": ("slither", "--detect out-of-order-retryable"),
        "FRONT_RUNNING": ("slither", "--detect out-of-order-retryable"),

        # Access control and kill paths
        "SUICIDAL": ("maian", "-c 0"),
        "PRODIGAL": ("maian", "-c 1"),
        "GREEDY": ("maian", "-c 2"),
        "ARBITRARY_SEND": ("slither", "--detect arbitrary-send-erc20, arbitrary-send-erc20-permit, arbitrary-send-eth"),

        # Arithmetic
        "OVERFLOW": ("mythril", "--modules IntegerArithmetics"),
        "UNDERFLOW": ("mythril", "--modules IntegerArithmetics"),

        # Visibility / authorization
        "UNINITIALIZED_STORAGE_POINTER": ("slither", "--detect uninitialized-storage"),
        "UNINITIALIZED_STORAGE": ("slither", "--detect uninitialized-state"),
        
        # Misc patterns
        "LOW_LEVEL_CALL": ("slither", "--detect low-level-calls"),
        "DELEGATECALL": ("mythril", "--modules ArbitraryDelegateCall"),
        "SELFDESTRUCT": ("maian", "-c 0"),
        "ASSERT_VIOLATION": ("mythril", "--modules Exceptions"),
        "WRITE_TO_ARBITRARY_STORAGE": ("mythril", "--modules ArbitraryStorage"),
        "BLOCK_DEPENDENCE": ("slither", "--detect timestamp"),
        "WEAK_RANDOMNESS": ("slither", "--detect weak-prng"),
        "VARIABLE_SHADOWING": ("slither", "--detect shadowing-state"),
        "DEPRECATED_FUNCTION": ("slither", "--detect deprecated-standards"),
        "UNUSED_STATE_VARIABLE": ("slither", "--detect unused-state"),
        "STRICT_BALANCE_EQUALITY": ("mythril", "--modules UnexpectedEther"),

        # Information disclosure
        "LEAK": ("slither", "--detect uninitialized-storage"),

        # Versioning & other
        "OUTDATED_COMPILER": ("slither", "--detect solc-version"),
        "VERSION_PRAGMA": ("slither", "--detect solc-version"),

    }

    # Map base tool names to their requested argument sets
    tool_args_map = {}

    existing_tool_keys = set()
    scheduled_tool_keys = set(scheduled_tools) if scheduled_tools else set()
    skip_after_no_args = False

    if task_settings:
        existing_tool_keys = getattr(task_settings, "tool_keys", set())
        skip_after_no_args = getattr(task_settings, "skip_after_no_args", False)

    # Collection of the requested argument sets in tool_args_map
    for vuln in vuln_list:
        for category in vuln.get("categories", []):
            tool_entry = VULN_TOOL_MAP.get(category)
            if not tool_entry:
                continue
            
            base_name = tool_entry[0].split("-")[0]
            args = tool_entry[1].strip()
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
        
        # Elaboration of the collected sets to create tool args
        scheduled = []
        for base_name, args_set in tool_args_map.items():
            # If a tool has no args, schedule it with just its base name
            if not args_set:    
                scheduled.append((base_name, ""))
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

            scheduled.append((base_name, " ".join(combined_parts)))

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
    for attempt in range(3):
        args_message = f"args: {task.tool_args}" if task.tool_args.strip() else "no args"
        sb.logging.message(f"\033[93mAttempt {attempt+1} of running {base_tool} with {args_message}\033[0m", "INFO")
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



def analyser(logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed, scheduled_tools):
        
    def pre_analysis():
        with tasks_started.get_lock():
            tasks_started_value = tasks_started.value + 1
            tasks_started.value = tasks_started_value
        sb.logging.message(
            f"Starting task {tasks_started_value}/{tasks_total.value}: {sb.colors.tool(task.tool.id)} and {sb.colors.file(task.relfn)}",
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

            if task.settings.dynamic:
                # Call reparse after tool execution
                tool_parsed_output = call_reparse(task.rdir)

                # Analyze the parsed results and select next tool
                vuln_list = analyze_parsed_results(tool_parsed_output)
                next_tools = route_next_tool(vuln_list, task.settings, scheduled_tools)

                # Prevent dynamic task duplication
                new_tool_added = False
                existing_tool_keys = getattr(task.settings, "tool_keys", set())
                skip_after_no_args = getattr(task.settings, "skip_after_no_args", False)
                for tool_name, tool_args in next_tools:
                    base_name = tool_name.split("-")[0]
                    tool_key = f"{base_name}|{tool_args.strip()}"
                    if skip_after_no_args and (f"{base_name}|" in existing_tool_keys or f"{base_name}|" in scheduled_tools):
                        sb.logging.message(f"Routing of {base_name} skipped: previous more complete execution already performed", "DEBUG")
                        continue
                    if tool_key in existing_tool_keys or tool_key in scheduled_tools:
                        continue

                    new_task = sb.smartbugs.collect_single_task(
                        task.absfn, task.relfn, tool_name, task.settings, tool_args
                    )
                    if new_task:
                        taskqueue.put(new_task)
                        scheduled_tools.append(tool_key)
                        existing_tool_keys.add(tool_key)
                        new_tool_added = True
                        with tasks_total.get_lock():
                            tasks_total.value += 1

                added_info = ', '.join(f"{t[0]}|{t[1]}" for t in next_tools) if next_tools else 'no tool'
                sb.logging.message(f"[{task.tool.id}] executed in {run_duration}, and added {added_info}.", "INFO")
            else:
                sb.logging.message(f"[{task.tool.id}] executed in {run_duration}.", "INFO")
 
        except sb.errors.SmartBugsError as e:
            duration = 0.0
            sb.logging.message(sb.colors.error(f"While analyzing {task.absfn} with {task.tool.id}:\n{e}"), "", logqueue)
        
        finally:
            # Ensure core tools are scheduled at least once
            scheduled_base_tools = {k.split("|")[0] for k in getattr(task.settings, "tool_keys", set())}
            scheduled_base_tools.update(k.split("|")[0] for k in scheduled_tools)

            if task.settings.dynamic:
                missing_core_tools = CORE_TOOLS - scheduled_base_tools
                
                if not new_tool_added and missing_core_tools:
                    next_tool = sorted(missing_core_tools)[0]
                    core_tool_key = f"{next_tool}|"
                    if core_tool_key in scheduled_tools:
                        continue                    
                    
                    new_task = sb.smartbugs.collect_single_task(task.absfn, task.relfn, next_tool, task.settings, "")
                    if new_task:
                        sb.logging.message(f"CORE TOOL ROUTE: SCHEDULING {next_tool}", "DEBUG")
                        taskqueue.put(new_task)
                        scheduled_tools.append(core_tool_key)                        
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

        # fill task queue using a joinable queue to wait for all tasks
        taskqueue = mp.JoinableQueue()

        for task in tasks:
            taskqueue.put(task)
 
        # accounting
        tasks_total = mp.Value('L', len(tasks))
        tasks_started = mp.Value('L', 0)
        tasks_completed = mp.Value('L', 0)
        time_completed = mp.Value('f', 0.0)

        # Use a multiprocessing.Manager for shared list
        manager = mp.Manager()
        scheduled_tools = manager.list()


        # start analysers
        shared = (logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed, scheduled_tools)
        analysers = [ mp.Process(target=analyser, args=shared) for _ in range(settings.processes) ]
        
        for a in analysers:
            a.start()

        # wait for all tasks to be marked as done
        taskqueue.join()
        sb.logging.message("Join completed — all tasks finished or accounted for.", "DEBUG")
        
        # now shut down workers
        for _ in range(settings.processes):
            taskqueue.put(None)
        # wait for analysers to finish
        for a in analysers:
            a.join()

        # good bye
        duration = datetime.timedelta(seconds=round(time.time()-start_time))
        sb.logging.message(f"Analysis completed in {duration}.", "", logqueue)

    finally:
        sb.logging.stop(logqueue)