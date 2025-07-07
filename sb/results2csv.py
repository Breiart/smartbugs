import argparse, csv, os, sys
import sb.cfg, sb.io, sb.utils, sb.vulnerability

analyzer = sb.vulnerability.VulnerabilityAnalyzer()

FIELDS = (
    "filename", "basename", "toolid", "toolmode", "tool_args", "parser_version", "runid",
    "start", "duration", "exit_code",  "findings", "classified", "infos", "errors", "fails")

def main():
    argparser = argparse.ArgumentParser(
        prog="results2csv",
        description="Write key information from runs to stdout, in csv format.")
    argparser.add_argument("-p",
        action='store_true',
        help="encode lists (findings, infos, errors, fails) as Postgres arrays")
    argparser.add_argument("-v",
        action='store_true',
        help="verbose: show progress")
    argparser.add_argument("-f",
        nargs="+",
        metavar="FIELD",
        type=str,
        choices=FIELDS,
        default=FIELDS,
        help=f"fields to include in the csv output; one or more of {', '.join(FIELDS)} (default: all)")
    argparser.add_argument("-x",
        nargs="+",
        metavar="FIELD",
        type=str,
        choices=FIELDS,
        default=[],
        help=f"fields to exclude from csv output; one or more of {', '.join(FIELDS)} (default: none excluded)")
    argparser.add_argument("results",
        nargs="+",
        metavar="DIR",
        help="directories containing the run results")

    if len(sys.argv)==1:
        argparser.print_help(sys.stderr)
        sys.exit(1)

    args = argparser.parse_args()

    fields = [ f for f in args.f if f not in args.x ]

    results = set()
    for r in args.results:
        for path,_,files in os.walk(r):
            if sb.cfg.TASK_LOG in files:
                results.add(path)

    csv_out = csv.writer(sys.stdout)
    csv_out.writerow(fields)
    for r in sorted(results):
        if args.v:
            print(r, file=sys.stderr)
        try:
            task_log = sb.io.read_json(os.path.join(r,sb.cfg.TASK_LOG))
        except Exception as e:
            print(f"Cannot read task log: {e}", file=sys.stderr)
            continue
        try:
            parser_output = sb.io.read_json(os.path.join(r,sb.cfg.PARSER_OUTPUT))
        except Exception as e:
            print(f"Cannot read parsed output; use 'reparse' to generate it.\n{e}", file=sys.stderr)
            continue
        csv_out.writerow(data2csv(task_log, parser_output, args.p, fields))



def list2postgres(l):
    es = []
    for e in l:
        if any (ch in e for ch in ('"', ",", "\n", "{", "}")):
            es.append('"'+e.replace('"','\\"')+'"')
        else:
            es.append(e)
    return "{" + ",".join(es) + "}"
        
def list2excel(l):
    es = []
    for e in l:
        if any (ch in e for ch in ('"', ",", "\n")):
            es.append('"'+e.replace('"','""')+'"')
        else:
            es.append(e)
    return ",".join(es)

def data2csv(task_log, parser_output, postgres, fields):
    csv = {
        "filename": task_log["filename"],
        "basename": os.path.basename(task_log["filename"]),
        "toolid": task_log["tool"]["id"],
        "toolmode": task_log["tool"]["mode"],
        "tool_args": parser_output.get("tool_args", task_log.get("tool_args", "")),
        "parser_version": parser_output["parser"]["version"],
        "runid": task_log["runid"],
        "start": task_log["result"]["start"],
        "duration": task_log["result"]["duration"],
        "exit_code": task_log["result"]["exit_code"],
        "findings": sorted({
            (sb.utils.str2label(f.get("name", "")) +
             (f"@{f['line']}" if str(f.get("line", "")).strip() else ""))
            for f in parser_output["findings"]}),
        "classified": [],
        "infos": parser_output["infos"],
        "errors": parser_output["errors"],
        "fails": parser_output["fails"],
    }
    for f in parser_output["findings"]:
        res = analyzer.classify_finding(task_log["tool"]["id"], f)
        line = f"@{res['line']}" if str(res.get('line', '')).strip() and res['line'] != -1 else ""
        for cat in res.get("categories", []):
            csv["classified"].append(f"{cat}{line}")
    csv["classified"] = sorted(set(csv["classified"]))
    for f in ("findings", "classified", "infos", "errors", "fails"):
        if postgres:
            csv[f] = list2postgres(csv[f])
        else:
            csv[f] = list2excel(csv[f])
    return [ csv[f] for f in fields ]


if __name__ == '__main__':
    sys.exit(main())
