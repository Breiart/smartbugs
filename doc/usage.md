# Usage

SmartBugs provides a command-line interface. Run it without arguments for a short description.
For details, see [SmartBugs' wiki](https://github.com/smartbugs/smartbugs/wiki/The-command-line-interface).

Dynamic scheduling of additional tools is enabled by default. Use `--no-dynamic` to run only the specified tools.

```console
./smartbugs
usage: smartbugs [-c FILE] [-t TOOL [TOOL ...]] [-f PATTERN [PATTERN ...]] [--main] [--runtime]
                 [--processes N] [--timeout N] [--time-budget N] [--cpu-quota N] [--mem-limit MEM] [--fuzz-mode MODE]
                 [--no-dynamic][--runid ID] [--results DIR] [--log FILE] [--overwrite] [--json] 
                 [--sarif] [--quiet] [--version] [-h]
...
```

**Example:** To analyse the Solidity files in the `samples` directory with Mythril, use the command

```console
./smartbugs -t mythril -f samples/*.sol --processes 2 --mem-limit 4g --timeout 600
```

The options tell SmartBugs to run two processes in parallel, with a memory limit of 4GB and max. 10 minutes computation time per task.
By default, the results are placed in the local directory `results`.
If a tool is run with additional arguments, these arguments are used as
a subfolder name inside the contract's directory so runs with different
arguments do not overwrite each other.
Fuzzing tools such as ConFuzzius honor the `--fuzz-mode` option, which
controls their execution time (`fast`, `normal`, or `accurate`).

Budgeted second phase
- `--time-budget N` reserves N seconds for a second orchestration phase after
  the core analysis completes. If the core analysis takes longer than N,
  nothing happens. If time remains, SmartBugs logs the remaining budget and
  automatically schedules additional analyses sized to use the remaining time.
  The current policy schedules missing tools for each contract in the order of
  the `all` alias (excluding `sfuzz`, which is used as a fallback) and sizes
  per-task timeouts from the remaining time. Tasks are planned round‑robin
  across files so that the combined workload aims to keep all processes busy
  for as long as possible within the budget. If the batch finishes early,
  further batches are planned until the time budget is exhausted or no more
  tasks are available.

Example:
```console
./smartbugs -t mythril -f samples/*.sol --timeout 600 --time-budget 900
```
Runs the normal orchestration first; if it finishes in under 15 minutes, the
remaining time is used to run Slither per the policy above.

Follow-up analyses scheduled dynamically by SmartBugs may also define a
timeout category (`fast`, `normal`, or `accurate`). The concrete durations for
these categories are configured in `sb/cfg.py` through the `FOLLOWUP_TIMEOUTS`
dictionary. Adjust those values to increase or decrease the allotted time for
follow-up runs or to introduce new timeout profiles.


## Utility programs

**`reparse`** can be used to parse analysis results and extract relevant information, without rerunning the analysis.
This may be useful either when you did not specify the option `--json` or `--sarif` during analysis, or when you want to parse old analysis results with an updated parser.

```console
./reparse
usage: reparse [-h] [--sarif] [--processes N] [-v] DIR [DIR ...]
```

**`results2csv`** generates a csv file from the results, suitable e.g. for a database.

```console
./results2csv
usage: results2csv [-h] [-p] [-v] [-f FIELD [FIELD ...]] [-x FIELD [FIELD ...]] DIR [DIR ...]
```

The following commands analyse `SimpleDAO.sol` with all available tools and write the parsed output to `results.csv`.
`reparse` is necessary in this example, since `smartbugs` is called without the options `--json` and `--sarif`, so SmartBugs doesn't parse during the analysis.
`results2csv` collects the outputs in the folder `results` and writes for each analysed contract one line of comma-separated values to standard output (redirected to `results.csv`).
The option `-p` tells `results2csv` to format the lists of findings, errors etc. as Postgres arrays; without the option, the csv file is suitable for spreadsheet programs.

```console
./smartbugs -t all -f samples/SimpleDAO.sol
./reparse results
./results2csv -p results > results.csv
```

You can then create an HTML report summarising the CSV files:

```console
./generate_report --input-folder results --output report.html
```

The report lists each contract’s classified vulnerabilities with line numbers and the tools that detected them.
