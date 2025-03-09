import docker, os, shutil, tempfile, requests, traceback
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



def __prettify_task_log(task):
    #Typeof task: <class 'sb.task.Task'>
    task = str(task) 
    try:
        parsed = json.loads(task)
        pretty = json.dumps(task, indent=4, sort_keys=True)
        # Colorare il JSON usando pygments (assicurarsi che il pacchetto pygments sia installato)
        colorful = highlight(pretty, lexers.JsonLexer(), formatters.TerminalFormatter())
        return colorful
    except Exception:
        #Fai il log del messaggio di errore con l'eccezione

        sb.logging.message(f"Error in __prettify_task_log() -> {task}", "ERROR")
        return task

import os
import json
from pygments import highlight, lexers, formatters
import sb.errors

def __docker_args(task, sbdir):
    print(f"DEBUG: Entering __docker_args() with task -> {__prettify_task_log(task)}")

    # Define default tool parameters
    tool_params = {
        "mythril": "--execution-timeout 1 --max-depth 64",
        "maian": "-s",
        "echidna": "--config config.yaml",
        "confuzzius": "--epochs 100"
    }

    # Initialize Docker arguments
    args = {
        "volumes": {sbdir: {"bind": "/sb", "mode": "rw"}},
        "detach": True,
        "user": 0,
        
    }

    print(f"DEBUG: Step 1 - Initialized args -> {args}")

    # Assign tool-specific settings
    for k in ("image", "cpu_quota", "mem_limit"):
        v = getattr(task.tool, k, None)
        if v is not None:
            args[k] = v
    for k in ("cpu_quota", "mem_limit"):
        v = getattr(task.settings, k, None)
        if v is not None:
            args[k] = v

    print(f"DEBUG: Step 2 - Assigned resource limits -> {args}")

    # Extract execution parameters
    filename = f"/sb/{os.path.split(task.absfn)[1]}"
    timeout = task.settings.timeout or "0"
    main = 1 if task.settings.main else 0

    print(f"\033[95mDEBUG: Step 3 - Extracted execution parameters -> filename: {filename}, timeout: {timeout}, main: {main}\033[0m")

    # Verify if the tool has a valid command function
    tool_command = None
    print(f"\033[92mDEBUG: Step 4 - task.tool -> {task.tool}\033[0m")
    if hasattr(task.tool, "command") and callable(task.tool.command):
        try:
            tool_command = task.tool.command(filename, timeout, "/sb/bin", main)
        except Exception as e:
            print(f"ERROR: Failed to generate tool command -> {e}")


    #print log di tool_command in colore verde
    
    print(f"\033[92mDEBUG: Step 4 - Generated tool_command -> {tool_command}\033[0m")

    # If tool_command is None or empty, check if entrypoint is available
    if not tool_command or tool_command.strip() == "":
        if hasattr(task.tool, "entrypoint") and task.tool.entrypoint:
            print(f"WARNING: tool_command is empty, falling back to entrypoint for {task.tool.id}")
            args["entrypoint"] = task.tool.entrypoint(filename, timeout, "/sb/bin", main)
            print(f"\033[91mDEBUG: Step 4 - Fallback to entrypoint -> {args['entrypoint']}\033[0m") 
        else:
            print(f"ERROR: No valid command or entrypoint found for tool {task.tool.id}")
            raise sb.errors.SmartBugsError(f"Invalid execution setup for tool {task.tool.id}")

    # Assign tool parameters
    base_tool_id = task.tool.id.split("-")[0]
    tool_params_str = tool_params.get(base_tool_id, "")

    print(f"DEBUG: Step 5 - Extracted tool parameters for {task.tool.id} -> {tool_params_str}")

    # Assign the final command if present
    if tool_command:
        args["command"] = f"{tool_command} {tool_params_str}".strip()
        print(f"DEBUG: Step 6 - Docker command set -> {args['command']}")

    # Print final Docker execution details
    print(f"DEBUG: Step 7 - FINAL DOCKER will execute -> {args}")

    return args



def execute(task):
    sbdir = __docker_volume(task)
    #print(f"DEBUG: Calling __docker_args() with task -> {task}")
    args = __docker_args(task, sbdir)
    print(f"DEBUG: __docker_args() returned -> {args}")

    exit_code,logs,output,container = None,[],None,None
    try:
        print(f"DEBUG: Docker execution arguments -> {args}")
        try:
            container = client().containers.run(**args)
        except Exception as e:
            print(f"ERROR: Failed to start Docker container -> {e}")
            raise
        print(f"DEBUG: Docker container started -> {container}")
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
        #raise sb.errors.SmartBugsError(f"Problem running Docker container: {e})")
        logs = container.logs().decode("utf8").splitlines() if container else []
        raise sb.errors.SmartBugsError(
            f"Docker execution failed for {task.tool.id}\nError: {e}\nLogs:\n" + "\n".join(logs)
        )

    finally:
        try:
            container.kill()
        except Exception:
            pass
        try:
            container.remove()
        except Exception:
            pass
        shutil.rmtree(sbdir)

    return exit_code, logs, output, args
