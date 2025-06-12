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
    vulnerabilities = set()    
    
    
    tool_id = parsed_output.get("parser", {}).get("id")
    
    analyzer = sb.vulnerability.VulnerabilityAnalyzer()
    vuln_list = analyzer.analyze(tool_id, parsed_output)

    print(f"DEBUG: VULN LIST: {vuln_list}")
    return vuln_list


def route_next_tool(vuln_list, task_settings=None):
    """
    Route to the next tool based on the list of detected vulnerabilities.
    Returns:
        str or None: Tool name or None if no mapping is found.
    """
    if not vuln_list:
        return []
    
    #FIXME Questa vuln tool map prima o poi verrà sostituita da un'implementazione di più alto livello
    VULN_TOOL_MAP = {
        # Reentrancy-related
        "REENTRANCY": ("mythril", "--modules ExternalCalls"),
        "UNLOCKED_ETHER": ("slither", "--detect reentrancy-eth, reentrancy-events, reentrancy-no-eth"),
        #"REENTRANCY_NO_GUARD": ("slither", "--reentrancy-no-guard"),

        # Transaction order
        "TOD": ("slither", "--detect out-of-order-retryable"),

        # Access control
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
        

        # Deprecated or unsafe patterns
        "LOW_LEVEL_CALL": ("slither", "--detect low-level-calls"),
        "DELEGATECALL": ("mythril", "--modules ArbitraryDelegateCall"),
        "SELFDESTRUCT": ("maian", "-c 0"),

        # Information disclosure
        "LEAK": ("slither", "--detect uninitialized-storage"),

        # Versioning & other
        "OUTDATED_COMPILER": ("slither", "--detect solc-version"),

        #TODO Needs to be correctly categorized
        #"UNRESTRICTED_WRITE": ("slither", ""),
    }

    scheduled = []
    seen_tools = set()

    existing_base_names = set()

    if task_settings:
        existing_base_names = {t.split("-")[0] for t in task_settings.tools}


    for vuln in vuln_list:
        for category in vuln.get("categories", []):
            tool_entry = VULN_TOOL_MAP.get(category)
            if tool_entry:
                base_name = tool_entry[0].split("-")[0]
                if base_name not in seen_tools and base_name not in existing_base_names:
                    scheduled.append(tool_entry)
                    #sb.logging.message(f"ROUTE NEXT TOOL: SCHEDULED {tool_entry}", "DEBUG")
                    seen_tools.add(base_name)

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
            if (not task.settings.overwrite and
                previous["tool"]["id"] == task.tool.id and
                previous["filename"] == task.relfn):
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
        sb.logging.message(f"\033[93mAttempt {attempt+1} of running {base_tool}\033[0m", "INFO")
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
            if task.relfn != old_fn or task.tool.id != old_toolid or task.tool.mode != old_mode:
                raise sb.errors.SmartBugsError(
                    f"Result directory {task.rdir} occupied by another task"
                    f" ({old_toolid}/{old_mode}, {old_fn})")

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

            # Call reparse after tool execution
            tool_parsed_output = call_reparse(task.rdir)

            # Analyze the parsed results and select next tool
            vuln_list = analyze_parsed_results(tool_parsed_output)
            next_tools = route_next_tool(vuln_list, task.settings)

            # Prevent dynamic task duplication
            new_tool_added = False
            existing_base_tools = {t.split("-")[0] for t in task.settings.tools}
            #if next_tool and next_tool.split("-")[0] not in existing_base_tools:
            #    new_task = sb.smartbugs.collect_single_task(task.absfn, task.relfn, next_tool, task.settings, tool_args)
            for tool_name, tool_args in next_tools:
                base_name = tool_name.split("-")[0]
                tool_key = f"{tool_name}|{tool_args.strip()}"
                if base_name in existing_base_tools:
                    continue
                if tool_key in scheduled_tools:
                    continue
                new_task = sb.smartbugs.collect_single_task(
                    task.absfn, task.relfn, tool_name, task.settings, tool_args
                )
                if new_task:
                    taskqueue.put(new_task)
                    scheduled_tools.append(tool_key)
                    new_tool_added = True
                    with tasks_total.get_lock():
                        tasks_total.value += 1
                        existing_base_tools.add(base_name)

            added_info = ', '.join(t[0] for t in next_tools) if next_tools else 'no tool'
            #sb.logging.message(f"[{task.tool.id}] executed in {run_duration}, and added {next_tool if next_tool else 'no tool'}.", "INFO")
            sb.logging.message(f"[{task.tool.id}] executed in {run_duration}, and added {added_info}.", "INFO")
 
        except sb.errors.SmartBugsError as e:
            duration = 0.0
            sb.logging.message(sb.colors.error(f"While analyzing {task.absfn} with {task.tool.id}:\n{e}"), "", logqueue)
        
        finally:

            #FIXME Soluzione temporanea per assicurarmi che i core tool runnino tutti
            if not new_tool_added:
                # Ensure core tools are scheduled at least once
                scheduled_base_tools = {t.split("-")[0] for t in task.settings.tools}
                missing_core_tools = CORE_TOOLS - scheduled_base_tools
                
                #TODO Aggiungere i tool mancanti uno ad uno, così da aumentare la possibilità che i successivi vengano chiamati con dei flag che ne consentano un'esecuzione mirata
                for missing_tool in missing_core_tools:
                    core_tool_key = f"{missing_tool}|"
                    if core_tool_key in scheduled_tools:
                        continue                    
                    new_task = sb.smartbugs.collect_single_task(
                        task.absfn, task.relfn, missing_tool, task.settings, ""
                    )
                    if new_task:
                        sb.logging.message(f"CORE TOOL ROUTE: SCHEDULING {missing_tool}", "DEBUG")
                        taskqueue.put(new_task)
                        scheduled_tools.append(core_tool_key)                        
                        with tasks_total.get_lock():
                            tasks_total.value += 1
                            existing_base_tools.add(missing_tool)        
            
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
        #TODO Assicurarsi che il manager sia a conoscenza di tutti i tool mentre vengono schedulati. Questo deve includere il tool di lancio
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