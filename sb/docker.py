import docker, os, shutil, tempfile, requests, traceback
import sb.io, sb.errors, sb.cfg



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
    tool_params = {
        "slither": "--detect reentrancy,unchecked-lowlevel",
        "mythril": "--execution-timeout 300 --max-depth 64",
        "maian": "-s",
        "echidna": "--config config.yaml",
        "confuzzius": "--epochs 100"
    }
    
    args = {
        "volumes": {sbdir: {"bind": "/sb", "mode": "rw"}},
        "detach": True,
        "user": 0
    }
    for k in ("image", "cpu_quota", "mem_limit"):
        v = getattr(task.tool, k, None)
        if v is not None:
            args[k] = v
    for k in ("cpu_quota", "mem_limit"):
        v = getattr(task.settings, k, None)
        if v is not None:
            args[k] = v
    filename = f"/sb/{os.path.split(task.absfn)[1]}"
    timeout = task.settings.timeout or "0"
    main = 1 if task.settings.main else 0
    
    #tool_command = task.tool.command(filename, timeout, "/sb/bin", main)

    print(f"DEBUG: Checking tool object for {task.tool.id} -> {task.tool}")

    if not hasattr(task.tool, "command") or task.tool.command is None:
        print(f"DEBUG: Manually setting command for {task.tool.id}")

        task.tool.command = lambda filename, timeout, bin, main: f"slither {filename} {task.tool.args}"

    tool_command = task.tool.command(filename, timeout, "/sb/bin", main)

    if not tool_command or tool_command.strip() == "":
        print(f"DEBUG: tool_command for {task.tool.id} is None or empty. Full tool object: {task.tool}")
        raise sb.errors.SmartBugsError(f"Invalid command for tool {task.tool.id}")

    print(f"DEBUG: tool_command for {task.tool.id} -> {tool_command}")


    print(f"DEBUG: tool_command for {task.tool.id} -> {tool_command}")


    #tool_params_str = tool_params.get(task.tool.id, "")

    base_tool_id = task.tool.id.split("-")[0]
    tool_params_str = tool_params.get(base_tool_id, "")

    print(f"DEBUG: tool_params for {task.tool.id} (base: {base_tool_id}) -> {tool_params_str}")    
    
    print(f"docker.py DEBUG: tool_params for {task.tool.id} -> {tool_params_str}")


    #args['command'] = f"{tool_command} {tool_params_str}".strip()
    
    # ME: Replaced from here
    if not tool_command or tool_command.strip() == "":
        print(f"docker.py DEBUG: tool_command for {task.tool.id} is None or empty")
        raise sb.errors.SmartBugsError(f"Invalid command for tool {task.tool.id}")

    print(f"docker.py DEBUG: tool_command for {task.tool.id} -> {tool_command}")

    args['command'] = f"{tool_command} {tool_params_str}".strip()
    # ME: to here
    
    args['entrypoint'] = task.tool.entrypoint(filename, timeout, "/sb/bin", main)
    
    return args



def execute(task):
    sbdir = __docker_volume(task)
    args = __docker_args(task, sbdir)
    exit_code,logs,output,container = None,[],None,None
    try:
        container = client().containers.run(**args)
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
