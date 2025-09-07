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

# Default timeouts (in seconds) for fuzzing tools based on the fuzz_mode
FUZZER_TIMEOUTS = {
    "fast": 120,
    "normal": 300,
    "accurate": 1000,
}

# Default timeouts (in seconds) for dynamically scheduled follow-up analyses.
# Individual entries in ``VULN_TOOL_MAP`` reference these identifiers to select
# an appropriate timeout for a follow-up run. Adjust the values here to change
# how long fast, normal, or accurate follow-up analyses may run.
FOLLOWUP_TIMEOUTS = {
    "fast": 150,
    "normal": 700,
    "accurate": 900,
}