import docker, os, shutil, tempfile, requests, traceback, json
import sb.io, sb.errors, sb.cfg
import sb.logging



_client = None

def client():
    global _client
    if not _client:
        try:    
            _client = docker.from_env()
            _client.info()
        except Exception:
            details = f"\n{traceback.format_exc()}" if sb.cfg.DEBUG else ""
            raise sb.errors.SmartBugsError(f"Docker: Cannot connect to service. Is it installed and running?{details}")
    return _client



images_loaded = set()

def is_loaded(image):
    if image in images_loaded:
        return True
    try:
        image_list = client().images.list(image)
    except Exception as e:
        raise sb.errors.SmartBugsError(f"Docker: checking for image {image} failed.\n{e}")
    if image_list:
        images_loaded.add(image)
        return True
    return False



def load(image):
    try:
        client().images.pull(image)
    except Exception as e:
        raise sb.errors.SmartBugsError(f"Docker: Loading image {image} failed.\n{e}")
    images_loaded.add(image)



def __docker_volume(task):
    sbdir = tempfile.mkdtemp()
    sbdir_bin = os.path.join(sbdir, "bin")
    if task.tool.mode in ("bytecode","runtime"):
        # sanitize hex code
        code = sb.io.read_lines(task.absfn)
        code = code[0].strip() if code else ""
        if code.startswith("0x"):
            code = code[2:]
        _,filename = os.path.split(task.absfn)
        sb.io.write_txt(os.path.join(sbdir,filename), code)
    else:
        shutil.copy(task.absfn, sbdir)
    if task.tool.bin:
        shutil.copytree(task.tool.absbin, sbdir_bin)
    else:
        os.mkdir(sbdir_bin)
    if task.solc_path:
        sbdir_bin_solc = os.path.join(sbdir_bin, "solc")
        shutil.copyfile(task.solc_path, sbdir_bin_solc)
    return sbdir



def __docker_args(task, sbdir):
    task.tool = task.tool.__class__.load_configuration(task.tool.id, getattr(task, "metadata", None))
    
    # Initialize Docker arguments
    args = {
        "volumes": {sbdir: {"bind": "/sb", "mode": "rw"}},
        "detach": True,
        "user": 0,        
    }

    # Assign tool-specific settings
    for k in ("image", "cpu_quota", "mem_limit"):
        v = getattr(task.tool, k, None)
        if v is not None:
            args[k] = v
    for k in ("cpu_quota", "mem_limit"):
        v = getattr(task.settings, k, None)
        if v is not None:
            args[k] = v

    # Extract execution parameters
    filename = f"/sb/{os.path.split(task.absfn)[1]}"
    timeout = task.settings.timeout or "0"
    main = 1 if task.settings.main else 0

    tool_args = task.tool_args
    #if tool_args and tool_args.strip() != "":
    #    sb.logging.message(f"DEBUG: Docker execute obtained tool args: {tool_args}", "INFO")


    # Verify if the tool has a valid command function
    tool_command = None
    if hasattr(task.tool, "command") and callable(task.tool.command):
        try:
            tool_command = task.tool.command(filename, timeout, "/sb/bin", main, tool_args)
        except Exception as e:
            sb.logging.message(f"ERROR: Failed to generate tool command -> {e}", "ERROR")

    # If tool_command is None or empty, check if entrypoint is available
    if not tool_command or tool_command.strip() == "":
        if hasattr(task.tool, "entrypoint") and task.tool.entrypoint:
            args["entrypoint"] = task.tool.entrypoint(filename, timeout, "/sb/bin", main, tool_args) 
        else:
            sb.logging.message(f"ERROR: No valid command or entrypoint found for tool {task.tool.id}", "ERROR")
            raise sb.errors.SmartBugsError(f"Invalid execution setup for tool {task.tool.id}")

    # Assign the tool command if present
    if tool_command:
        args["command"] = f"{tool_command} {tool_args}".strip()
        #sb.logging.message(f"DEBUG: Docker command set -> {args['command']}", "INFO")

    return args



def execute(task):
    sbdir = __docker_volume(task)
    args = __docker_args(task, sbdir)

    exit_code,logs,output,container = None,[],None,None
    try:
        try:
            container = client().containers.run(**args)
        except Exception as e:
            print(f"ERROR: Failed to start Docker container -> {e}")
            raise
        print(f"Docker container started: {container}")
        try:
            result = container.wait(timeout=task.settings.timeout)
            exit_code = result["StatusCode"]
        except (requests.exceptions.ReadTimeout,requests.exceptions.ConnectionError):
            try:
                container.stop(timeout=10)
            except docker.errors.APIError:
                pass
        logs = container.logs().decode("utf8").splitlines()
        if task.tool.output:
            try:
                output,_ = container.get_archive(task.tool.output)
                output = b''.join(output)
            except docker.errors.NotFound:
                pass

    except Exception as e:
        logs = container.logs().decode("utf8").splitlines() if container else []
        raise sb.errors.SmartBugsError(f"Docker execution failed for {task.tool.id}\nError: {e}\nLogs:\n" + "\n".join(logs))

    finally:
        try:
            container.kill()
        except Exception as e:
            pass
        try:
            container.remove()
        except Exception:
            pass
        shutil.rmtree(sbdir)

    return exit_code, logs, output, args
