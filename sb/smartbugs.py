import glob, os, operator
import sb.tools, sb.solidity, sb.tasks, sb.docker, sb.analysis, sb.colors, sb.logging, sb.cfg, sb.io, sb.settings, sb.errors



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


def collect_single_task(absfn, relfn, tool_name, settings):
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
    
    print(f"\033[94m[DEBUG] Loaded tool.id = {tool}\033[0m")
    
    # Prevent duplicates based on tool name
    base_tool_name = tool.id.split("-")[0]
    existing_base_names = {t.split("-")[0] for t in settings.tools}
    print(f"[DEBUG] Comparing base_tool_name = {base_tool_name} with {existing_base_names}")
    if base_tool_name in existing_base_names:
        sb.logging.message(f"\033[93m[collect_single_task] Tool '{tool_name}' already scheduled. Skipping.\033[0m", "INFO")
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
            raise sb.errors.SmartBugsError(f"{relfn}: no pragma, cannot determine solc version")
        if not sb.solidity.ensure_solc_versions_loaded():
            sb.logging.message(sb.colors.warning(
                "Failed to load list of solc versions; are we connected to the internet? Proceeding with local compilers"),
                "")
        solc_version = sb.solidity.get_solc_version(pragma)
        if not solc_version:
            raise sb.errors.SmartBugsError(f"{relfn}: no compiler found that matches {pragma}")
        solc_path = sb.solidity.get_solc_path(solc_version)
        if not solc_path:
            raise sb.errors.SmartBugsError(f"{relfn}: cannot load solc {solc_version} needed by {tool.id}")

    ensure_loaded(tool.image)

    # Update tool list on settings
    print(f"[DEBUG] Appending tool to settings.tools: {tool.id}")
    settings.tools.append(tool.id)

    # Return a Task object updated with the new tool
    rdir = settings.resultdir(tool.id, tool.mode, absfn, relfn)
    return sb.tasks.Task(absfn, relfn, rdir, solc_version, solc_path, tool, settings)


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
            raise sb.errors.SmartBugsError(f"{fn}: no pragma, cannot determine solc version")
        if not sb.solidity.ensure_solc_versions_loaded():
            sb.logging.message(sb.colors.warning(
                "Failed to load list of solc versions; are we connected to the internet? Proceeding with local compilers"),
                "")
        solc_version = sb.solidity.get_solc_version(pragma)
        if not solc_version:
            raise sb.errors.SmartBugsError(f"{fn}: no compiler found that matches {pragma}")
        solc_path = sb.solidity.get_solc_path(solc_version)
        if not solc_path:
            raise sb.errors.SmartBugsError(f"{fn}: cannot load solc {solc_version} needed by {toolid}")
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

            #print(f"DEBUG: Checking tool {tool.id} entrypoint: {tool.entrypoint('/samples/SimpleDAO.sol', 300, '/sb/bin', None)}")

            if not tool.entrypoint:
                print(f"DEBUG: Tool {tool.id} has no entrypoint.")

            if ((is_sol and tool.mode=="solidity") or
                (is_byc and tool.mode=="bytecode") or
                (is_rtc and tool.mode=="runtime")):

                # find unique name for result dir
                # ought to be the same when rerunning SB with the same args,
                # due to sorting files and tools
                base = settings.resultdir(tool.id,tool.mode,absfn,relfn)
                rdir = disambiguate(base)

                # load resources
                solc_version, solc_path = None,None
                if tool.solc:
                    try:
                        solc_version, solc_path = get_solc(pragma, relfn, tool.id)
                    except Exception as e:
                        exceptions.append(e)
                ensure_loaded(tool.image)

                task = sb.tasks.Task(absfn,relfn,rdir,solc_version,solc_path,tool,settings)
                tasks.append(task)

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
