
import os
import argparse
import pandas as pd
from pathlib import Path
import plotly.express as px
from jinja2 import Template
import re
import sb.vulnerability

def _seconds_to_hms(seconds: float) -> str:
    """Return the given duration in ``HH:MM:SS`` format."""
    seconds = int(round(float(seconds)))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def load_csvs(input_folder: str) -> pd.DataFrame:
    """Load all CSV files from ``input_folder`` into a single dataframe.

    The returned dataframe contains an ``Execution ID`` column taken from the
    ``runid`` field of each CSV, if present.  If ``runid`` is missing, the file
    name (without the ``.csv`` extension) is used as a fallback.  This allows
    comparing multiple executions even when they are stored in the same CSV
    file.
    """
    all_data = []
    for file in sorted(os.listdir(input_folder)):
        if file.lower().endswith(".csv"):
            path = os.path.join(input_folder, file)
            try:
                df = pd.read_csv(path)
                runid_col = next((c for c in df.columns if c.lower() == "runid"), None)
                if runid_col:
                    df["Execution ID"] = df[runid_col].astype(str)
                else:
                    df["Execution ID"] = file.replace(".csv", "")
                all_data.append(df)
            except Exception as e:
                print(f"Error reading {file}: {e}")
    if not all_data:
        raise ValueError("No CSV files found in input folder")
    df = pd.concat(all_data, ignore_index=True)
    # normalise column names coming from results2csv
    rename_map = {}
    if "toolid" in df.columns and "tool" not in df.columns:
        rename_map["toolid"] = "tool"
    if "duration" in df.columns and "execution_time" not in df.columns:
        rename_map["duration"] = "execution_time"
    if "tool_args" in df.columns and "arguments" not in df.columns:
        rename_map["tool_args"] = "arguments"
    if "findings" in df.columns and "vulnerabilities" not in df.columns:
        rename_map["findings"] = "vulnerabilities"
    if "classified_findings" in df.columns and "categories" not in df.columns:
        rename_map["classified_findings"] = "categories"
    df.rename(columns=rename_map, inplace=True)
    return df

def _split_values(cell: str) -> list:
    """Split a delimited cell into individual values.

    Handles formats like:
    - "{a,b}" (postgres array)
    - "{\"a\",\"b\"}" (quoted postgres array)
    - "a,b" (plain CSV-joined)
    - "a|b" (legacy pipe-joined)
    """
    s = str(cell)
    if not s or s.lower() == "none":
        return []
    # normalize and strip containers
    s = s.strip().strip("{}[]")
    s = s.replace("|", ",")
    if not s:
        return []
    values = []
    if '"' in s:
        # Extract quoted or unquoted tokens separated by commas
        import re as _re
        for m in _re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"|([^,]+)', s):
            token = m.group(1) if m.group(1) is not None else m.group(2)
            if token is None:
                continue
            token = token.strip()
            # Unescape quotes inside quoted strings
            token = token.replace('\\"', '"')
            if token:
                values.append(token)
    else:
        values = [v.strip() for v in s.split(",") if v.strip()]
    # Final cleanup: strip any surrounding single quotes
    return [v.strip("'\"") for v in values if v]

def _count_vulns(cell: str) -> int:
    return len(_split_values(cell))


def clean_and_process(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare dataframe for report generation."""
    # Fill missing values only in object columns to avoid casting warnings
    object_cols = df.select_dtypes(include=["object"]).columns
    if len(object_cols):
        df[object_cols] = df[object_cols].fillna("")
    if "execution_time" in df.columns:
        df["execution_time"] = pd.to_numeric(df["execution_time"], errors="coerce").fillna(0)
    # Ensure a vulnerabilities column exists before counting
    if "vulnerabilities" not in df.columns:
        df["vulnerabilities"] = ""
    df["Vulnerabilities Count"] = df["vulnerabilities"].apply(_count_vulns)
    if "categories" in df.columns:
        df["Categories Count"] = df["categories"].apply(lambda c: len(_split_values(c)))
    return df

def _join_vulns(series: pd.Series) -> str:
    values = set()
    for sub in series:
        for v in _split_values(sub):
                values.add(v)
    return ", ".join(sorted(values))

def _parse_vuln_entry(entry: str):
    """Return (name, line) tuple parsed from a vulnerability entry string.

    The line is returned as a string or ``None`` if no location is found.
    """
    entry = entry.strip()
    if not entry or entry.lower() == "none":
        return None

    # Common patterns where the line number is clearly separated from the name
    patterns = [
        r"^(?P<name>.+?)[@:]\s*(?P<line>\d+(?:,\d+)*)$",
        r"^(?P<name>.+?)\(\s*line\s*(?P<line>\d+(?:,\d+)*)\s*\)$",
        r"^(?P<name>.+?)\s+line\s+(?P<line>\d+(?:,\d+)*)$",
    ]
    for pat in patterns:
        m = re.search(pat, entry, re.IGNORECASE)
        if m:
            return m.group("name").strip(), m.group("line")

    return entry, None


def render_html(df, output_file):
    per_tool = (
        df.groupby(["Execution ID", "tool"])
        .agg(
            **{
                "Avg Exec Time (s)": ("execution_time", "mean"),
                "Total Runs": ("execution_time", "count"),
                "Total Vulns Found": ("Vulnerabilities Count", "sum"),
                "Detected Vulns": ("vulnerabilities", _join_vulns),
                "Contracts": ("basename", lambda x: ", ".join(sorted(set(x)))),
            }
        )
        .reset_index()
    )

    per_vuln_rows = []
    analyzer = sb.vulnerability.VulnerabilityAnalyzer()
    tool_summaries = []

    for (exec_id, contract), group in df.groupby(["Execution ID", "basename"]):
        vuln_tools = {}
        for _, row in group.iterrows():
            for v in _split_values(row.get("vulnerabilities", "")):
                parsed = _parse_vuln_entry(v)
                if not parsed:
                    continue
                name, line = parsed
                key = (name, line or "")
                vuln_tools.setdefault(key, set()).add(row.get("tool", ""))
        for (name, line), tools in vuln_tools.items():
            per_vuln_rows.append({
                "Execution ID": exec_id,
                "Contract": contract,
                "Vulnerability": name,
                "Line": line or "",
                "Tools": ", ".join(sorted(tools))
            })
    per_vuln = pd.DataFrame(per_vuln_rows)

    for (exec_id, tool), group in df.groupby(["Execution ID", "tool"]):
        total_time = group["execution_time"].sum()
        findings = []
        for _, row in group.iterrows():
            for v in _split_values(row.get("vulnerabilities", "")):
                parsed = _parse_vuln_entry(v)
                if not parsed:
                    continue
                name, line = parsed
                result = analyzer.classify_finding(row.get("tool", ""), {"name": name, "line": line})
                categories = result.get("categories", [])
                cat_str = ", ".join(categories)
                findings.append({
                    "Contract": row.get("basename", ""),
                    "Line": line or "",
                    "Category": cat_str,
                    "Vulnerability": name,
                })
        tool_summaries.append({
            "Execution ID": exec_id,
            "Tool": tool,
            "Exec Time": _seconds_to_hms(total_time),
            "Total Vulns": len(findings),
            "Findings": findings,
        })
    
    analysis_summary = (
        df.groupby("Execution ID")
          .agg({"basename": lambda x: ", ".join(sorted(set(x)))})
          .reset_index()
          .rename(columns={"basename": "Contracts"})
    )

    per_execution = (
        df.groupby("Execution ID")
          .agg(
              total_time=("execution_time", "sum"),
              total_vulns=("Vulnerabilities Count", "sum"),
          )
          .reset_index()
    )
    
    per_execution_numeric = per_execution.rename(
        columns={"total_time": "Total Exec Time", "total_vulns": "Total Vulns Found"}
    )
    
    # Prepare a human-readable version (if needed later) without relying on undefined variables
    per_execution = per_execution.rename(
        columns={
            "total_time": "Total Exec Time",
            "total_vulns": "Total Vulns Found",
        }
    )
    per_execution["Total Exec Time"] = per_execution["Total Exec Time"].apply(_seconds_to_hms)
    
    overall = {
        "Total Executions": df["Execution ID"].nunique(),
        "Total Time": _seconds_to_hms(df["execution_time"].sum()),
        "Total Vulns Found": df["Vulnerabilities Count"].sum()
    }

    # Build per-run summary including duration, vulnerabilities found and classified count
    # Aggregate classified counts from tool_summaries to avoid re-parsing
    run_classified = {}
    run_found = {}
    for ts in tool_summaries:
        exec_id = ts["Execution ID"]
        found = len(ts.get("Findings", []))
        classified = 0
        for f in ts.get("Findings", []):
            cat = str(f.get("Category", "")).strip()
            if cat and cat.upper() != "UNCLASSIFIED":
                classified += 1
        run_found[exec_id] = run_found.get(exec_id, 0) + found
        run_classified[exec_id] = run_classified.get(exec_id, 0) + classified

    # Merge with per_execution to get total exec time per run (already HH:MM:SS)
    per_run_table = []
    exec_time_map = {row["Execution ID"]: row["Total Exec Time"] for _, row in per_execution.iterrows()}
    exec_ids = sorted(set(list(run_found.keys()) + list(exec_time_map.keys())))
    for eid in exec_ids:
        per_run_table.append({
            "Execution ID": eid,
            "Exec Time": exec_time_map.get(eid, _seconds_to_hms(0)),
            "Vulns Found": int(run_found.get(eid, 0)),
            "Classified": int(run_classified.get(eid, 0)),
        })


    fig_time = px.bar(
        per_tool,
        x="tool",
        y="Avg Exec Time (s)",
        color="Execution ID",
        barmode="group",
        title="Average Execution Time per Tool",
    )
    fig_vuln = px.bar(
        per_tool,
        x="tool",
        y="Total Vulns Found",
        color="Execution ID",
        barmode="group",
        title="Total Vulnerabilities Found per Tool",
    )

    fig_scatter = px.scatter(
        per_execution_numeric,
        x="Total Exec Time",
        y="Total Vulns Found",
        hover_name="Execution ID",
        title="Execution Time vs Vulnerabilities Found",
    )

    template_path = Path(__file__).resolve().parents[1] / "templates" / "report_template.html"
    with open(template_path) as f:
        template = Template(f.read())

    with open(output_file, "w") as f:
        f.write(
            template.render(
                executions=df.to_dict(orient="records"),
                analysis_summary=analysis_summary.to_dict(orient="records"),
                per_run_summary=per_run_table,
                vuln_summary=per_vuln.to_dict(orient="records"),
                tool_summary=tool_summaries,
                overall=overall,
                fig_time=fig_time.to_html(full_html=False, include_plotlyjs="cdn"),
                fig_vuln=fig_vuln.to_html(full_html=False, include_plotlyjs=False),
                fig_scatter=fig_scatter.to_html(full_html=False, include_plotlyjs=False),
            )
        )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_folder", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    df = load_csvs(args.input_folder)
    df = clean_and_process(df)
    render_html(df, args.output)

if __name__ == "__main__":
    main()
