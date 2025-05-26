import multiprocessing, random, time, datetime, os, random, subprocess
import json
import sb.logging, sb.colors, sb.docker, sb.cfg, sb.io, sb.parsing, sb.sarif, sb.errors
import sb.smartbugs
import sb.tools


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


def call_reparse(smartbugs_root, results_directory, processes=1, generate_sarif=False, verbose=True):
    # Calls the existing reparse script after each tool execution
    reparse_script = os.path.join(smartbugs_root, 'reparse')

    if not os.path.isfile(reparse_script):
        raise FileNotFoundError(f"Reparse script not found at {reparse_script}")

    if not os.access(reparse_script, os.X_OK):
        raise PermissionError(f"Reparse script is not executable: {reparse_script}")

    cmd = [
        reparse_script,
        "--processes", str(processes)
    ]

    if generate_sarif:
        cmd.append("--sarif")
    if verbose:
        cmd.append("-v")

    cmd.append(results_directory)

    try:
        completed_process = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            cwd=smartbugs_root  # Important: run inside project root
        )

        if completed_process.stderr:
            sb.logging.message(f"Reparse stderr:\n{completed_process.stderr}", "WARNING")

        parser_output_path = os.path.join(results_directory, sb.cfg.PARSER_OUTPUT)
        if os.path.exists(parser_output_path):
            parsed_output = sb.io.read_json(parser_output_path)
            sb.logging.message(f"Parsed output successfully read from {parser_output_path}", "INFO")
            return parsed_output
        else:
            sb.logging.message(f"Parsed output file not found at {parser_output_path}", "ERROR")
            return None

    except subprocess.CalledProcessError as e:
        sb.logging.message(f"Reparse subprocess failed:\n{e.stderr}", "ERROR")
        return None
    except json.JSONDecodeError as e:
        sb.logging.message(f"Failed to parse JSON output: {e}", "ERROR")
        return None


def save_execution_results(task, tool_log, tool_output, docker_args, exit_code, start_time, duration):
    """Save tool execution results immediately after running a tool."""

    def sanitize_bytes(obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")  # Convert bytes to str
        if isinstance(obj, dict):
            return {k: sanitize_bytes(v) for k, v in obj.items()}  # Recursively clean values
        if isinstance(obj, list):
            return [sanitize_bytes(i) for i in obj]  # Recursively clean list elements
        return obj  # Return as-is if not bytes, list, or dict

    # Step 0: Ensure result directory exists
    if not os.path.exists(task.rdir):
        os.makedirs(task.rdir, exist_ok=True)
        sb.logging.message(f"Result directory {task.rdir} created.", "DEBUG")

    # Step 1: Check if we are overwriting old data (optional but good)
    tool_log_path = os.path.join(task.rdir, sb.cfg.TOOL_LOG)
    tool_output_path = os.path.join(task.rdir, sb.cfg.TOOL_OUTPUT)
    task_log_path = os.path.join(task.rdir, sb.cfg.TASK_LOG)

    if any(os.path.exists(p) for p in (tool_log_path, tool_output_path, task_log_path)):
        sb.logging.message(f"Warning: Overwriting existing tool result files in {task.rdir}", "WARNING")

    # Step 2: Save tool log (join lines and write text)
    tool_log_text = "\n".join(tool_log)
    sb.io.write_txt(tool_log_path, tool_log_text)
    
    # Step 3: Sanitize and then save tool output (JSON)
    safe_tool_output = sanitize_bytes(tool_output)
    sb.io.write_json(tool_output_path, safe_tool_output)

    # Step 4: Save task log (JSON)
    task_log_dict_obj = task_log_dict(
        task=task,
        start_time=start_time,
        duration=duration,
        exit_code=exit_code,
        log=bool(tool_log),
        output=bool(tool_output),
        docker_args=docker_args
    )
    sb.io.write_json(task_log_path, task_log_dict_obj)

    sb.logging.message(f"Execution results saved to {task.rdir}", "DEBUG")


def analyze_parsed_results(parsed_output):
    # Placeholder analysis implementation
    # TODO implement logic to analyze the parsed output. This logic has to be passed to choose_next_tool

    parser_id = parsed_output["parser"]["id"]
    
    if parser_id == "mythril-0.24.7":
        return "mythril"
    elif parser_id == "slither-0.10.4":
        return "slither"
    
    sb.logging.message(f"Warning: No analysis rule defined for parser ID '{parser_id}'", "WARNING")
    return None

def choose_next_tool(analysis):
    # Placeholder logic for future next tool selection 
    # Future logic to choose next tool based on the analysis of the parsed output
    # TODO implement logic to choose the next tool based on the parsed output
    
    if analysis == "slither":
        return "mythril"
    elif analysis == "mythril":
        return "maian"
    
    return None

def update_task_for_next_tool(task, parsed_result, next_tool, tool_order):
    """
    Update task for the next tool based on parsed results.
    Currently a placeholder
    # TODO implement logic to update the task for the next tool
    """

    #if next_tool not in task.settings.tools:
    existing_base_ids = {t.split("-")[0] for t in task.settings.tools}
    if next_tool.split("-")[0] not in existing_base_ids:
        task.settings.tools.append(next_tool)
    if next_tool not in tool_order:
        tool_order.append(next_tool)

    return task



def execute(task, taskqueue, tasks_total):    
    # create result dir if it doesn't exist
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
                return 0.0, False
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

    # Execute tool with retry mechanism
    base_tool = task.tool.id.split("-")[0]
    executed = False
    total_duration = 0.0
    new_tool_added = False
    tool_log = tool_output = docker_args = None
       
    for attempt in range(3):
        sb.logging.message(f"\033[93mAttempt {attempt+1} of running {base_tool}\033[0m", "INFO")
        try:
            start_time = time.time()                    
            exit_code,tool_log,tool_output,docker_args = sb.docker.execute(task)                    
            duration = time.time() - start_time
            total_duration += duration
            executed = True

            sb.logging.message(f"{base_tool} executed in: {total_duration} seconds with exit code {exit_code}", "INFO")

            # Save outputs to disk
            save_execution_results(task, tool_log, tool_output, docker_args, exit_code, start_time, duration)
                    
            # Call reparse after tool execution
            smartbugs_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            tool_parsed_output = call_reparse(
                smartbugs_root=smartbugs_root,
                results_directory=task.rdir,
                generate_sarif=False,
                verbose=True
            )

            # Analyze the parsed results and select next tool
            analysis = analyze_parsed_results(tool_parsed_output)
            next_tool = choose_next_tool(analysis)

            # Prevent dynamic task duplication
            existing_base_tools = {t.split("-")[0] for t in task.settings.tools}
            if next_tool and next_tool.split("-")[0] not in existing_base_tools:
                new_task = sb.smartbugs.collect_single_task(task.absfn, task.relfn, next_tool, task.settings)
                if new_task:
                    taskqueue.put(new_task)
                    with tasks_total.get_lock():
                        tasks_total.value += 1
                    new_tool_added = True

            if next_tool:
                sb.logging.message(f"{base_tool} selected next tool: {next_tool}", "INFO")
            else:
                sb.logging.message("No next tool selected.", "INFO")

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
            #if os.path.exists(fn_task_log) and not task.settings.overwrite:
            #    return 0.0, False

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

    sb.logging.message(f"TOOL {base_tool} completed execution.", "INFO")
    print(total_duration)
    print(new_tool_added)

    return total_duration, new_tool_added



def analyser(logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed):
        
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
        # estimated time to completion = time_so_far / completed_tasks * remaining_tasks / no_processes
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
            run_duration, new_tool_added = execute(task, taskqueue, tasks_total)
            print(f"[{task.tool.id}] received run_duration: {run_duration}, and added {new_tool_added}")
            duration += run_duration
 
        except sb.errors.SmartBugsError as e:
            duration = 0.0
            sb.logging.message(sb.colors.error(f"While analyzing {task.absfn} with {task.tool.id}:\n{e}"), "", logqueue)
        
        finally:
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

        # start analysers
        shared = (logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed)
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