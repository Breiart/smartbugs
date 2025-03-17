import multiprocessing, random, time, datetime, os, random
import sb.logging, sb.colors, sb.docker, sb.cfg, sb.io, sb.parsing, sb.sarif, sb.errors



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



def execute(task):
    """
    ME: Execute the different tools in the predefined order with predefined configurations
    """
    tool_order = ["slither", "mythril", "maian", "echidna", "confuzzius"]

    # create result dir if it doesn't exist
    os.makedirs(task.rdir, exist_ok=True)
    if not os.path.isdir(task.rdir):
        raise sb.errors.SmartBugsError(f"Cannot create result directory {task.rdir}")

    # Cleanup old results
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

    # Execute tools in order with retry mechanism
    for tool in tool_order:
        #LOG - Tool execution
        
        if task.tool.id.startswith(tool):
            for i in range(3):
                sb.logging.message(f"\033[93mAttempt {i+1} of running {tool}\033[0m", "INFO")
                try:
                    start_time = time.time()

                    exit_code,tool_log,tool_output,docker_args = sb.docker.execute(task)
                    duration = time.time() - start_time
                    if exit_code == 0:
                        break
                except sb.errors.SmartBugsError as e:
                    if i == 2:
                        raise
                
                sleep_duration = random.randint(1, 2) * 30
                sb.logging.message(f"\033[93mSleeping for {sleep_duration} seconds before retry...\033[0m", "INFO")
                sleep_start_time = time.time()
                sb.logging.message(f"\033[93mSleep started at {datetime.datetime.fromtimestamp(sleep_start_time)}\033[0m", "INFO")
                time.sleep(sleep_duration)
            if exit_code != 0:
                sb.logging.message(f"{tool} execution failed with exit code {exit_code}", "WARNING")

    
    sb.logging.message("All tools executed in the predefined order.", "INFO")

    
    # check whether result dir is empty,
    # and if not, whether we are going to overwrite it
    fn_task_log = os.path.join(task.rdir, sb.cfg.TASK_LOG)
    if os.path.exists(fn_task_log):
        old = sb.io.read_json(fn_task_log)
        old_fn = old["filename"]
        old_toolid = old["tool"]["id"]
        old_mode = old["tool"]["mode"]
        if task.relfn != old_fn or task.tool.id != old_toolid or task.tool.mode != old_mode:
            raise sb.errors.SmartBugsError(
                f"Result directory {task.rdir} occupied by another task"
                f" ({old_toolid}/{old_mode}, {old_fn})")
        if not task.settings.overwrite:
            return 0.0

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

    return duration



def analyser(logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed):
        
    def pre_analysis():
        with tasks_started.get_lock():
            tasks_started_value = tasks_started.value + 1
            tasks_started.value = tasks_started_value
        sb.logging.message(
            f"Starting task {tasks_started_value}/{tasks_total}: {sb.colors.tool(task.tool.id)} and {sb.colors.file(task.relfn)}",
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
        remaining_tasks = tasks_total - tasks_completed_value
        if timeout:
            # Assume that the first round of processes all ran into a timeout
            sb.logging.message(f"\033[95mConsidering timeout for ETC calculation\033[0m", "INFO")
            completed_tasks += no_processes
            time_so_far += timeout*no_processes
        etc = time_so_far / completed_tasks * remaining_tasks / no_processes
        etc_fmt = datetime.timedelta(seconds=round(etc))
        duration_fmt = datetime.timedelta(seconds=round(duration))
        sb.logging.message(f"{tasks_completed_value}/{tasks_total} completed, ETC {etc_fmt}")

    while True:
        task = taskqueue.get()
        if task is None:
            return
        sb.logging.quiet = task.settings.quiet
        pre_analysis()
        try:
            duration = execute(task)
        except sb.errors.SmartBugsError as e:
            duration = 0.0
            sb.logging.message(sb.colors.error(f"While analyzing {task.absfn} with {task.tool.id}:\n{e}"), "", logqueue)
        post_analysis(duration, task.settings.processes, task.settings.timeout)



def run(tasks, settings):
    # spawn processes (instead of forking), for identical behavior on Linux and MacOS
    mp = multiprocessing.get_context("spawn")

    # start shared logging
    logqueue = mp.Queue()
    sb.logging.start(settings.log, settings.overwrite, logqueue)
    try:
        start_time = time.time()

        # ME: Define the specific order of tools to be used
        tool_order = ['slither', 'mythril', 'maian', 'echidna', 'confuzzius']

        # fill task queue
        taskqueue = mp.Queue()
        #random.shuffle(tasks)  # ME: replace this with the ordered version

        ordered_tasks = sorted(tasks, key=lambda task: next((i for i, tool in enumerate(tool_order) if task.tool.id.startswith(tool)), len(tool_order)))


        for task in ordered_tasks:
            taskqueue.put(task)
        for _ in range(settings.processes):
            taskqueue.put(None)

        # accounting
        tasks_total = len(tasks)
        tasks_started = mp.Value('L', 0)
        tasks_completed = mp.Value('L', 0)
        time_completed = mp.Value('f', 0.0)

        # start analysers
        shared = (logqueue, taskqueue, tasks_total, tasks_started, tasks_completed, time_completed)
        analysers = [ mp.Process(target=analyser, args=shared) for _ in range(settings.processes) ]
        for a in analysers:
            a.start()

        # wait for analysers to finish
        for a in analysers:
            a.join()

        # good bye
        duration = datetime.timedelta(seconds=round(time.time()-start_time))
        sb.logging.message(f"Analysis completed in {duration}.", "", logqueue)

    finally:
        sb.logging.stop(logqueue)

