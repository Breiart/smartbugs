import os, string
import sb.io, sb.cfg, sb.errors



FIELDS = ("id","mode","image","name","origin","version","info","parser",
    "output","bin", "default_params", "solc","cpu_quota","mem_limit","command","entrypoint")

class Tool():

    def __init__(self, cfg):
        #print(f"DEBUG: Tool configuration loaded -> {cfg}")  # Debugging
        for k in FIELDS:
            v = cfg.get(k)

            # For default_params, if not provided, default to empty string.
            if k == "default_params":
                v = str(v) if v is not None else ""
            
            if v is not None:
                if k in ("solc"):
                    try:
                        v = bool(v)
                    except Exception:
                        raise sb.errors.SmartBugsError(f"Tool: value of attribute '{k}' is not a Boolean.\n{cfg}")
                elif k in ("cpu_quota"):
                    try:
                        v = int(v)
                        assert v >= 0
                    except Exception:
                        raise sb.errors.SmartBugsError(f"Tool: value of attribute '{k}' is not an integer>=0.\n{cfg}")
                elif k in ("mem_limit"):
                    try:
                        v = str(v).replace(" ","")
                        if v[-1] in "kKmMgG":
                            assert int(v[:-1]) > 0
                        else:
                            assert int(v) > 0
                    except Exception:
                        raise sb.errors.SmartBugsError(f"Tool: value of attribute '{k}' is not a valid memory specifcation.\n{cfg}")
                else:
                    try:
                        v = str(v)
                    except Exception:
                        raise sb.errors.SmartBugsError(f"Tool: value of attribute '{k}' is not a string.\n{cfg}")
            if k in ("command","entrypoint"):
                k = f"_{k}"
                v = string.Template(v) if v else None
            setattr(self, k, v)
                
        for k in ("id", "mode"):
            if not getattr(self, k):
                raise sb.errors.InternalError(f"Tool: Field '{k}' missing.\n{cfg}")
        if not self.image:
            raise sb.errors.SmartBugsError(f"Tool {self.id}/{self.mode}: no image specified")
        extras = set(cfg.keys()).difference(FIELDS)
        if extras:
            raise sb.errors.SmartBugsError(f"Tool {self.id}/{self.mode}: extra field(s) {', '.join(extras)}")
        if not self._command and not self._entrypoint:
            raise sb.errors.SmartBugsError(f"Tool {self.id}/{self.mode}: neither command nor entrypoint specified.")
        if not self.parser:
            self.parser = sb.cfg.TOOL_PARSER
        if self.bin:
            self.absbin = os.path.join(sb.cfg.TOOLS_HOME,self.id,self.bin)
        #print(f"DEBUG: Loaded tool {self.id}, entrypoint = {self._entrypoint}")


    def command(self, filename, timeout, bin, main, args=""):
        cmd = self._command.substitute(FILENAME=filename, TIMEOUT=timeout, BIN=bin, MAIN=main, ARGS=args) if self._command else None
        try:
            return self._command.substitute(FILENAME=filename, TIMEOUT=timeout, BIN=bin, MAIN=main, ARGS=args) if self._command else None
        except KeyError as e:
            raise sb.errors.SmartBugsError(f"Unknown variable '{e}' in command of tool {self.id}/{self.mode}")


    def entrypoint(self, filename, timeout, bin, main, args=""):
        if self._entrypoint:
            substituted_entrypoint = self._entrypoint.substitute(FILENAME=filename, TIMEOUT=timeout, BIN=bin, MAIN=main, ARGS=args)
            # print(f"DEBUG: Entrypoint substitution - Original: {self._entrypoint.template}")
            # print(f"DEBUG: Entrypoint substitution - Values -> filename={filename}, timeout={timeout}, bin={bin}, main={main}", "args={args}")
            # print(f"DEBUG: Entrypoint substitution - Result: {substituted_entrypoint}")
            return substituted_entrypoint
        else:
            print("DEBUG: Entrypoint is None")
            return None
        try:
            return self._entrypoint.substitute(FILENAME=filename, TIMEOUT=timeout, BIN=bin, MAIN=main) if self._entrypoint else None
        except KeyError as e:
            raise sb.errors.SmartBugsError(f"Unknown variable '{e}' in entrypoint of tool {self.id}/{self.mode}")


    def dict(self):
        d = {}
        for k,v in self.__dict__.items():
            if k == "_command":
                d["command"] = self._command.template if self._command else None
            elif k == "_entrypoint":
                d["entrypoint"] = self._entrypoint.template if self._entrypoint else None
            elif k == "absbin":
                # We do not want to leak private information, like the full path, into log files
                pass
            else:
                d[k] = v
        return d


    def __str__(self):
        l = [ f"{k}: {str(v)}" for k,v in self.dict().items() ]
        return f"{{{', '.join(l)}}}"
        

    @classmethod
    def load_configuration(cls, tool_name, metadata=None):
        """
        Load and return a Tool instance for the given tool_name.
        Optionally adjust the configuration using metadata.

        For this example, we assume that each tool has a default YAML configuration file
        in sb.cfg.TOOLS_HOME/{tool_name}/{sb.cfg.TOOL_CONFIG}.
        """

        toolpath = os.path.join(sb.cfg.TOOLS_HOME, tool_name)
        fn = os.path.join(toolpath, sb.cfg.TOOL_CONFIG)
        cfg = sb.io.read_yaml(fn)

        # If the configuration uses an "alias", load that instead.
        if cfg.get("alias"):
            return cls.load_configuration(cfg["alias"], metadata)

        # Set the tool id for later use
        cfg["id"] = tool_name

        # Select a mode; here, you might choose based on context. For example:
        for mode in ("solidity", "bytecode", "runtime"):
            if mode in cfg:
                cfg_copy = cfg.copy()
                for m in ("solidity", "bytecode", "runtime"):
                    cfg_copy.pop(m, None)
                cfg_copy["mode"] = mode
                cfg_copy.update(cfg[mode])
                cfg = cfg_copy
                break

        # Adjust configuration based on metadata if necessary.
        if metadata and metadata.get("vulnerabilities"):
            vulns = metadata["vulnerabilities"]
            # Example: if many vulnerabilities were found, add an extra flag to the command.
            extra_flag = "--deep-analysis" if len(vulns) > 3 else ""
            if "command" in cfg:
                command_template = string.Template(cfg["command"])
                # You might embed extra_flag into the command. This is just one approach.
                cfg["command"] = command_template.template.replace("$ARGS", f"$ARGS {extra_flag}")

        return cls(cfg)




def load(ids, tools = [], seen = set()):
    """Load tool specifications

    Parameters
    ----------
    ids: list[str]
        list of strings identifying the tools
    tools: list[Tool]
        list of tool specifications already loaded
    seen: set[str]
        list of tool ids and tool aliases already processed

    Returns
    -------
    list[Tool]
        list of tool specifications corresponding to parameter ids
    """

    for id in ids:
        if id in seen:
            continue
        seen.add(id)
        toolpath = os.path.join(sb.cfg.TOOLS_HOME, id)
        fn = os.path.join(toolpath, sb.cfg.TOOL_CONFIG)
        cfg = sb.io.read_yaml(fn)

        alias = cfg.get("alias")
        if alias:
            load(alias, tools, seen)
            continue

        cfg["id"] = id
        found = False
        for mode in ("solidity", "bytecode", "runtime"):
            if mode not in cfg:
                continue
            found = True
            cfg_copy = cfg.copy()
            for m in ("solidity", "bytecode", "runtime"):
                cfg_copy.pop(m,None)
            cfg_copy["mode"] = mode
            if not isinstance(cfg[mode], dict):
                raise sb.errors.SmartBugsError(f"Tool {id}/{mode}: key/value mapping expected.")
            cfg_copy.update(cfg[mode])
            tools.append(Tool(cfg_copy))
        if not found:
            raise sb.errors.SmartBugsError(f"{fn}: needs one of the attributes 'alias', 'solidity', 'bytecode', 'runtime'")
    return tools



# the contents of tools/.../findings.yaml is cached, once per process
info_findings = {}

def info_finding(tool_id, fname):
    if tool_id not in info_findings:
        try:
            fn = os.path.join(sb.cfg.TOOLS_HOME, tool_id, sb.cfg.TOOL_FINDINGS)
            info_findings[tool_id] = sb.io.read_yaml(fn)
        except Exception:
            info_findings[tool_id] = {}
    info = info_findings[tool_id].get(fname)
    return {} if info is None else info
