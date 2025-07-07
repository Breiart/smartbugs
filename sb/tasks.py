class Task:
    def __init__(self, absfn, relfn, rdir, solc_version, solc_path, tool, settings, tool_args="", timeout=None):
        self.absfn = absfn # absolute normalized path
        self.relfn = relfn # path within project
        self.rdir = rdir   # directory for results
        self.solc_version = solc_version
        self.solc_path = solc_path
        self.tool = tool
        self.settings = settings
        self.tool_args = tool_args
        self.timeout = timeout

    def __str__(self):
        s = [ f"{k}: {str(v)}" for k,v in self.__dict__.items() ]
        return f"{{{', '.join(s)}}}"
