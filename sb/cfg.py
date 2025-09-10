import os, time, cpuinfo, platform

VERSION = "2.0.10"
HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SITE_CFG = os.path.join(HOME,"site_cfg.yaml")
TASK_LOG = "smartbugs.json"
TOOLS_HOME = os.path.join(HOME,"tools")
TOOL_CONFIG = "config.yaml"
TOOL_FINDINGS = "findings.yaml"
TOOL_PARSER = "parser.py"
TOOL_LOG = "result.log"
TOOL_OUTPUT = "result.tar"
PARSER_OUTPUT = "result.json"
SARIF_OUTPUT = "result.sarif"

CPU = cpuinfo.get_cpu_info()
UNAME = platform.uname()
PLATFORM = {
    "smartbugs": VERSION,
    "python": CPU.get("python_version"),
    "system": UNAME.system,
    "release": UNAME.release,
    "version": UNAME.version,
    "cpu": CPU.get("brand_raw"),
}

DEBUG = False

# Unified timeout configuration (in seconds), flat mapping.
#
# Keys may be:
# - Preset ids used by the orchestrator (e.g., 'fast', 'normal', 'accurate', 'maian').
# - Tool names for first/core runs, mapped to a fixed number of seconds.
TIMEOUTS = {
    # Follow-up presets (used by analysis orchestrator via timeout ids)
    "fast": 15,
    "normal": 500,
    "accurate": 900,
    "maian": 45,

    # Tool-specific timeouts for initial/core runs (optional)
    # "slither": 120,
    # "mythril": 600,
    # "confuzzius": 100,
    # "sfuzz": 100,

    # Core timeout label for ConFuzzius
    "confuzzius_core": 50,
}
