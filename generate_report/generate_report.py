
import os
import argparse
import pandas as pd
import plotly.express as px
from jinja2 import Template

def load_csvs(input_folder):
    all_data = []
    for file in os.listdir(input_folder):
        if file.endswith(".csv"):
            path = os.path.join(input_folder, file)
            try:
                df = pd.read_csv(path)
                df["Execution ID"] = file.replace(".csv", "")
                all_data.append(df)
            except Exception as e:
                print(f"Error reading {file}: {e}")
    return pd.concat(all_data, ignore_index=True)

def clean_and_process(df):
    df.fillna("None", inplace=True)
    df["Vulnerabilities Count"] = df["vulnerabilities"].apply(lambda x: len(str(x).split("|")) if x != "None" else 0)
    return df

def render_html(df, output_file):
    per_tool = df.groupby("tool").agg({
        "execution_time": "mean",
        "Execution ID": "count",
        "Vulnerabilities Count": "sum",
        "vulnerabilities": lambda x: ", ".join(sorted(set(v for sub in x for v in str(sub).split("|") if v != "None")))
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

    template_path = os.path.join(os.path.dirname(__file__), "template.html")
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
