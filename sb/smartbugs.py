import glob, os, operator
import sb.tools, sb.solidity, sb.tasks, sb.docker, sb.analysis, sb.colors, sb.logging, sb.cfg, sb.io, sb.settings, sb.errors

# Tools that rely on fuzzing strategies
FUZZER_TOOLS = {"confuzzius", "sfuzz"}

def _parse_arg_map(arg_str: str):
    """Return a mapping of flag prefixes to sets of values.

    This helper is used to check if a new set of arguments is a subset of a
    previously executed one. Flags without values are stored with an empty
    string in the value set.
    """
    arg_map = {}
    if not arg_str:
        return arg_map
    
    tokens = arg_str.strip().split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith('-'):
            prefix = token
            values = []
            value_tokens = []
            
            # handle --flag=value or -f=value forms
            if '=' in token:
                prefix, after = token.split('=', 1)
                if after:
                    value_tokens.append(after)
            else:
                # look ahead for a value that does not start with '-'
                i += 1
                while i < len(tokens) and not tokens[i].startswith('-'):
                    value_tokens.append(tokens[i])
                    i += 1
            for vt in value_tokens:
                for val in vt.split(','):
                    val = val.strip().strip(',')
                    if val:
                        values.append(val)
            if not values:
                values = ['']
            existing = arg_map.setdefault(prefix, set())
            existing.update(values)
            continue
        i += 1

    return arg_map

def collect_files(patterns):
    files = []
    for root,spec in patterns:
        if spec.endswith(".sbd"):
            contracts = []
            for sbdfile in glob.glob(spec, recursive=True):
                contracts.extend(sb.io.read_lines(sbdfile))
        elif root:
            try:
                contracts = glob.glob(spec, root_dir=root, recursive=True)
            except TypeError:
                raise sb.errors.SmartBugsError(f"{root}:{spec}: colons in file patterns only supported for Python>=3.10")
        else: # avoid root_dir, compatibility with python<3.10
            contracts = glob.glob(spec, recursive=True)

        for relfn in contracts:
            root_relfn = os.path.join(root,relfn) if root else relfn
            absfn = os.path.normpath(os.path.abspath(root_relfn))
            if os.path.isfile(absfn) and absfn[-4:] in (".hex", ".sol"):
                files.append( (absfn,relfn) )
    return files


def collect_single_task(absfn, relfn, tool_name, settings, tool_args):
    """
    Creates a new Task object for a dynamically added tool if it hasn't already been scheduled.
    """
    
    def ensure_loaded(image):
        if not sb.docker.is_loaded(image):
            sb.logging.message(f"Loading docker image {image}, may take a while ...")
            sb.docker.load(image)
    
    try:
        loaded = sb.tools.load([tool_name])
        tool = next((t for t in loaded if t.id.split("-")[0] == tool_name), None)
        if not tool:
            raise sb.errors.SmartBugsError(f"No matching tool found for '{tool_name}' after loading.")
    except Exception as e:
        raise sb.errors.SmartBugsError(f"Could not load tool '{tool_name}': {e}")
    
    # Prevent duplicates based on (tool name, arguments) tuple
    base_tool_name = tool.id.split("-")[0]
    clean_args = tool_args.strip()
    tool_key = f"{base_tool_name}|{tool_args.strip()}"
    
    tool_key_map = getattr(settings, "tool_keys", {})
    if isinstance(tool_key_map, set):
        tool_key_map = {absfn: tool_key_map}
        settings.tool_keys = tool_key_map
    elif not isinstance(tool_key_map, dict):
        tool_key_map = {}
        settings.tool_keys = tool_key_map
    existing_keys = tool_key_map.setdefault(absfn, set())
    
    # Skip scheduling if the exact tool/args pair was already seen
    if tool_key in existing_keys:
        sb.logging.message(f"\033[93m[collect_single_task] Tool '{tool_name}' with args '{tool_args}' already scheduled. Skipping.\033[0m", "INFO")
        return None
    
    # Skip scheduling if the argument set is a subset of a previously executed one
    existing_arg_history = getattr(settings, "tool_arg_history", {})
    new_arg_map = _parse_arg_map(clean_args)
    old_map = existing_arg_history.get(base_tool_name, {})
    if new_arg_map:
        subset = True
        for flag, values in new_arg_map.items():
            if not values <= old_map.get(flag, set()):
                subset = False
                break
        if subset:
            sb.logging.message(f"\033[93m[collect_single_task] Tool '{tool_name}' with args '{tool_args}' is subset of previous run. Skipping.\033[0m", "INFO")
            return None
    
    # If a run without arguments has been scheduled and the feature is enabled,
    # avoid scheduling further runs of the tool with any arguments.
    if (getattr(settings, "skip_after_no_args", False) and f"{base_tool_name}|" in existing_keys):
        sb.logging.message(f"\033[93m[collect_single_task] Tool '{tool_name}' already scheduled without args. Skipping additional run.\033[0m","INFO")
        return None


    is_sol = absfn[-4:] == ".sol"
    is_byc = absfn[-4:] == ".hex" and not (absfn[-7:-4] == ".rt" or settings.runtime)
    is_rtc = absfn[-4:] == ".hex" and (absfn[-7:-4] == ".rt" or settings.runtime)

    if not ((is_sol and tool.mode == "solidity") or
            (is_byc and tool.mode == "bytecode") or
            (is_rtc and tool.mode == "runtime")):
        return None

    pragma, contractnames = None, []
    if is_sol:
        prg = sb.io.read_lines(absfn)
        pragma, contractnames = sb.solidity.get_pragma_contractnames(prg)
        contract = os.path.basename(absfn)[:-4]
        if settings.main and contract not in contractnames:
            raise sb.errors.SmartBugsError(f"Contract '{contract}' not found in {absfn}")

    # Load resources
    solc_version, solc_path = None, None
    if tool.solc:
        if not pragma:
            sb.logging.message(sb.colors.warning(f"{relfn}: no pragma, skipping {tool.id}"), "")
            return None
        if not sb.solidity.ensure_solc_versions_loaded():
            sb.logging.message(sb.colors.warning(
                "Failed to load list of solc versions; are we connected to the internet? Proceeding with local compilers"),
                "")
        solc_version = sb.solidity.get_solc_version(pragma)
        if not solc_version:            
            sb.logging.message(sb.colors.warning(f"{relfn}: pragma {pragma} requires unsupported solc, skipping {tool.id}"), "")
            return None
        solc_path = sb.solidity.get_solc_path(solc_version)
        if not solc_path:
            sb.logging.message(sb.colors.warning(f"{relfn}: cannot load solc {solc_version} needed by {tool.id}, skipping"), "")
            return None

    ensure_loaded(tool.image)

    # Determine timeout for fuzzers
    timeout = settings.timeout
    if not timeout and base_tool_name in FUZZER_TOOLS:
        timeout = sb.cfg.FUZZER_TIMEOUTS.get(
            getattr(settings, "fuzz_mode", "normal"),
            sb.cfg.FUZZER_TIMEOUTS["normal"],
        )

    settings.tools.append(tool.id)
    if hasattr(settings, "tool_keys"):
        tool_key_map = settings.tool_keys
        if isinstance(tool_key_map, set):
            tool_key_map = {absfn: tool_key_map}
            settings.tool_keys = tool_key_map
        elif not isinstance(tool_key_map, dict):
            tool_key_map = {}
            settings.tool_keys = tool_key_map
        tool_key_map.setdefault(absfn, set()).add(tool_key)
    if hasattr(settings, "tool_arg_history"):
        hist = settings.tool_arg_history.setdefault(base_tool_name, {})
        for flag, values in new_arg_map.items():
            hist.setdefault(flag, set()).update(values)

    # Return a Task object updated with the new tool
    rdir = settings.resultdir(tool.id, tool.mode, absfn, relfn, clean_args)
    return sb.tasks.Task(absfn, relfn, rdir, solc_version, solc_path, tool, settings, tool_args, timeout)


def collect_tasks(files, tools, settings):
    used_rdirs = set()
    rdir_collisions = 0

    def disambiguate(base):
        nonlocal rdir_collisions
        cnt = 1
        rdir = base
        collision = 0
        while rdir in used_rdirs:
            collision = 1
            cnt += 1
            rdir = f"{base}_{cnt}"
        used_rdirs.add(rdir)
        rdir_collisions += collision
        return rdir

    def report_collisions():
        if rdir_collisions > 0:
            sb.logging.message(
                sb.colors.warning(f"{rdir_collisions} collision(s) of result directories resolved."), "")
            if rdir_collisions > len(files)*0.1:
                sb.logging.message(sb.colors.warning(
                    "    Consider using more of $TOOL, $MODE, $ABSDIR, $RELDIR, $FILENAME,\n"
                    "    $FILEBASE, $FILEEXT when specifying the 'results' directory."))

    def get_solc(pragma, fn, toolid):
        if not pragma:
            sb.logging.message(sb.colors.warning(f"{fn}: no pragma, skipping {toolid}"), "")
            return None, None
        if not sb.solidity.ensure_solc_versions_loaded():
            sb.logging.message(sb.colors.warning(
                "Failed to load list of solc versions; are we connected to the internet? Proceeding with local compilers"),
                "")
        solc_version = sb.solidity.get_solc_version(pragma)
        if not solc_version:
            sb.logging.message(sb.colors.warning(f"{fn}: pragma {pragma} requires unsupported solc, skipping {toolid}"), "")
            return None, None
        solc_path = sb.solidity.get_solc_path(solc_version)
        if not solc_path:
            sb.logging.message(sb.colors.warning(f"{fn}: cannot load solc {solc_version} needed by {toolid}, skipping"), "")
            return None, None
        return solc_version,solc_path

    def ensure_loaded(image):
        if not sb.docker.is_loaded(image):
            sb.logging.message(f"Loading docker image {image}, may take a while ...")
            sb.docker.load(image)


    tasks = []
    exceptions = []

    last_absfn = None
    for absfn,relfn in sorted(files):
        if absfn == last_absfn:
            # ignore duplicate contracts
            continue
        last_absfn = absfn

        is_sol = absfn[-4:]==".sol"
        is_byc = absfn[-4:]==".hex" and not (absfn[-7:-4]==".rt" or settings.runtime)
        is_rtc = absfn[-4:]==".hex" and     (absfn[-7:-4]==".rt" or settings.runtime)

        contract = os.path.basename(absfn)[:-4]
        pragma,contractnames = None,[]
        if is_sol:
            prg = sb.io.read_lines(absfn)
            pragma,contractnames = sb.solidity.get_pragma_contractnames(prg)
            if settings.main and contract not in contractnames:
                exceptions.append(f"Contract '{contract}' not found in {absfn}")

        for tool in sorted(tools, key=operator.attrgetter("id", "mode")):

            if not tool.entrypoint:
                print(f"DEBUG: Tool {tool.id} has no entrypoint.")

            if ((is_sol and tool.mode=="solidity") or
                (is_byc and tool.mode=="bytecode") or
                (is_rtc and tool.mode=="runtime")):

                # find unique name for result dir
                # ought to be the same when rerunning SB with the same args,
                # due to sorting files and tools
                base = settings.resultdir(tool.id,tool.mode,absfn,relfn, "")
                rdir = disambiguate(base)

                # load resources
                solc_version, solc_path = None,None
                if tool.solc:
                    solc_version, solc_path = get_solc(pragma, relfn, tool.id)
                    if not solc_version or not solc_path:
                        continue
                ensure_loaded(tool.image)

                base_tool_name = tool.id.split("-")[0]
                core_arg_map = dict(sb.analysis.CORE_TOOLS)
                task_args = core_arg_map.get(base_tool_name, "")
                task_timeout = settings.timeout
                if not task_timeout and base_tool_name in FUZZER_TOOLS:
                    task_timeout = sb.cfg.FUZZER_TIMEOUTS.get(
                        getattr(settings, "fuzz_mode", "normal"),
                        sb.cfg.FUZZER_TIMEOUTS["normal"],
                    )

                task = sb.tasks.Task(absfn,relfn,rdir,solc_version,solc_path,tool,settings,task_args,task_timeout)
                tasks.append(task)
                if hasattr(settings, "tool_keys"):
                    base_tool_name = tool.id.split("-")[0]
                    tool_key_map = settings.tool_keys
                    if isinstance(tool_key_map, set):
                        tool_key_map = {absfn: tool_key_map}
                        settings.tool_keys = tool_key_map
                    elif not isinstance(tool_key_map, dict):
                        tool_key_map = {}
                        settings.tool_keys = tool_key_map
                    tool_key_map.setdefault(absfn, set()).add(f"{base_tool_name}|")

    report_collisions()
    if exceptions:
        errors = "\n".join(sorted({str(e) for e in exceptions}))
        raise sb.errors.SmartBugsError(f"Error(s) while collecting tasks:\n{errors}")
    return tasks



def main(settings: sb.settings.Settings):
    settings.freeze()
    sb.logging.quiet = settings.quiet
    sb.logging.message(
        sb.colors.success(f"Welcome to SmartBugs {sb.cfg.VERSION}!"),
        f"Settings: {settings}")

    tools = sb.tools.load(settings.tools)
    if not tools:
        sb.logging.message(sb.colors.warning("Warning: no tools selected!"))

    sb.logging.message("Collecting files ...")
    files = collect_files(settings.files)
    sb.logging.message(f"{len(files)} files to analyse")

    sb.logging.message("Assembling tasks ...")
    tasks = collect_tasks(files, tools, settings)
    sb.logging.message(f"{len(tasks)} tasks to execute")

    sb.analysis.run(tasks, settings)
