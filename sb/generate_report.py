
import os
import argparse
import pandas as pd
from pathlib import Path
import plotly.express as px
from jinja2 import Template


def load_csvs(input_folder: str) -> pd.DataFrame:
    """Load all CSV files from ``input_folder`` into a single dataframe."""
    all_data = []
    for file in sorted(os.listdir(input_folder)):
        if file.lower().endswith(".csv"):
            path = os.path.join(input_folder, file)
            try:
                df = pd.read_csv(path)
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

def render_html(df, output_file):
    per_tool = df.groupby("tool").agg({
        "execution_time": "mean",
        "Execution ID": "count",
        "Vulnerabilities Count": "sum",
        "vulnerabilities": lambda x: ", ".join(sorted({v.strip() for sub in x for v in str(sub).replace("|", ",").split(",") if v.strip() and v.lower() != 'none'}))
    }).reset_index().rename(columns={
        "execution_time": "Avg Exec Time (s)",
        "Execution ID": "Total Runs",
        "Vulnerabilities Count": "Total Vulns Found",
        "vulnerabilities": "Detected Vulns"
    })

    overall = {
        "Total Executions": df["Execution ID"].nunique(),
        "Total Time": df["execution_time"].sum(),
        "Total Vulns Found": df["Vulnerabilities Count"].sum()
    }

    fig_time = px.bar(per_tool, x="tool", y="Avg Exec Time (s)", title="Average Execution Time per Tool")
    fig_vuln = px.bar(per_tool, x="tool", y="Total Vulns Found", title="Total Vulnerabilities Found per Tool")
    fig_scatter = px.scatter(df, x="execution_time", y="Vulnerabilities Count", color="tool",
                             hover_data=["Execution ID"], title="Time vs Vulnerabilities Found")

    template_path = Path(__file__).resolve().parents[1] / "templates" / "report_template.html"
    with open(template_path) as f:
        template = Template(f.read())

    with open(output_file, "w") as f:
        f.write(template.render(
            executions=df.to_dict(orient="records"),
            summary=per_tool.to_dict(orient="records"),
            overall=overall,
            fig_time=fig_time.to_html(full_html=False, include_plotlyjs='cdn'),
            fig_vuln=fig_vuln.to_html(full_html=False, include_plotlyjs=False),
            fig_scatter=fig_scatter.to_html(full_html=False, include_plotlyjs=False)
        ))

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
