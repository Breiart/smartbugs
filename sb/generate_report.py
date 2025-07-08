
import os
import argparse
import pandas as pd
from pathlib import Path
import plotly.express as px
from jinja2 import Template
import re


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
    df.rename(columns=rename_map, inplace=True)
    return df

def _count_vulns(cell: str) -> int:
    cell = str(cell).strip('{}[]')
    if not cell or cell.lower() == 'none':
        return 0
    cell = cell.replace('|', ',')
    return len([v for v in cell.split(',') if v.strip()])

def clean_and_process(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare dataframe for report generation."""
    # Fill missing values only in object columns to avoid casting warnings
    object_cols = df.select_dtypes(include=["object"]).columns
    if len(object_cols):
        df[object_cols] = df[object_cols].fillna("")
    if "execution_time" in df.columns:
        df["execution_time"] = pd.to_numeric(df["execution_time"], errors="coerce").fillna(0)
    df["Vulnerabilities Count"] = df.get("vulnerabilities", "").apply(_count_vulns)
    return df

def _join_vulns(series: pd.Series) -> str:
    values = set()
    for sub in series:
        for v in str(sub).replace("|", ",").split(","):
            v = v.strip()
            if v and v.lower() != "none":
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
    for (exec_id, contract), group in df.groupby(["Execution ID", "basename"]):
        vuln_tools = {}
        for _, row in group.iterrows():
            vulns = str(row.get("vulnerabilities", "")).replace("|", ",")
            for v in vulns.strip('{}[]').split(','):
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


    analysis_summary = (
        df.groupby("Execution ID")
          .agg({"basename": lambda x: ", ".join(sorted(set(x)))})
          .reset_index()
          .rename(columns={"basename": "Contracts"})
    )

    per_execution = (
        df.groupby("Execution ID")
          .agg(
              **{
                  "Total Exec Time": ("execution_time", "sum"),
                  "Total Vulns Found": ("Vulnerabilities Count", "sum"),
                  "Total Runs": ("execution_time", "count"),
              }
          )
          .reset_index()
    )

    overall = {
        "Total Executions": df["Execution ID"].nunique(),
        "Total Time": _seconds_to_hms(df["execution_time"].sum()),
        "Total Vulns Found": df["Vulnerabilities Count"].sum()
    }


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
    fig_scatter = px.scatter(df, x="execution_time", y="Vulnerabilities Count", color="tool",
                             hover_data=["Execution ID"], title="Time vs Vulnerabilities Found")

    template_path = Path(__file__).resolve().parents[1] / "templates" / "report_template.html"
    with open(template_path) as f:
        template = Template(f.read())

    with open(output_file, "w") as f:
        f.write(
            template.render(
                executions=df.to_dict(orient="records"),
                analysis_summary=analysis_summary.to_dict(orient="records"),
                vuln_summary=per_vuln.to_dict(orient="records"),
                executions_summary=per_execution.to_dict(orient="records"),
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
