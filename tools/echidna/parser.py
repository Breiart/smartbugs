import io
import json
import tarfile
import re
import sb.parse_utils

VERSION = "2024/04/30"

LOCATION = re.compile(r"/sb/(.*?)#([0-9-]*)")

def parse(exit_code, log, output):
    findings = []
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)

    # Extract output file (assuming Echidna produces JSON output)
    try:
        with io.BytesIO(output) as o, tarfile.open(fileobj=o) as tar:
            output_json = tar.extractfile("echidna.json").read()
            output_dict = json.loads(output_json)
    except Exception as e:
        fails.add(f"Error parsing Echidna results: {e}")
        output_dict = {}

    if "error" in output_dict:
        errors.add("Echidna reported an error.")

    # Extract vulnerabilities
    for contract, results in output_dict.items():
        for vuln in results.get("errors", []):
            finding = {
                "contract": contract,
                "error": vuln.get("title", "Unknown Issue"),
                "description": vuln.get("description", "No description available"),
                "severity": vuln.get("severity", "Unknown"),
            }

            # Extract location if available
            m = LOCATION.search(finding["description"])
            if m:
                finding["filename"] = m[1]
                finding["line"] = int(m[2]) if "-" not in m[2] else int(m[2].split("-")[0])

            findings.append(finding)

    return findings, set(), errors, fails

