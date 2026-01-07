# Smartbugs Orchestrator

This repository contains the **thesis code release** of an evidence-driven orchestrator built on top of the **SmartBugs** framework for Ethereum smart-contract analysis.

It extends SmartBugs with orchestration logic that can **adapt tool selection and time budgets** based on evidence gathered during analysis, while retaining SmartBugs’ containerized execution model and result parsing pipeline.

## Thesis snapshot and reproducibility

This repository is intended to be cited as a **reproducible artifact** for the experiments discussed in the thesis.

- Use the tagged release **`v1.0-thesis`** (or the commit hash referenced in the thesis) to obtain the exact snapshot used for evaluation.
- If you are reading this repository from a branch other than the thesis tag, results may differ.

## What’s included

- SmartBugs-based CLI workflow for running analyses in Docker
- Orchestration layer (adaptive routing / scheduling policies)
- Normalization and parsing utilities to enable cross-tool aggregation
- (Optional) scripts to generate CSV/HTML summaries from result folders (inherited from SmartBugs)

## Requirements

- Docker (required)
- Python 3 (required)
- A Unix-like shell environment (Linux/macOS recommended; Windows supported via WSL)

## Installation

Follow the SmartBugs installation notes:
- `doc/installation.md`

> This project inherits most operational requirements from SmartBugs (Docker-based tool execution, Python entrypoints, etc.).

## Quick start

Example: run a SmartBugs analysis, reparse results (optional) and generate a report (input folder must contain at least one .csv file):

```bash
./smartbugs -t slither -f samples/OriginalSamples/*
./reparse results
./results2csv -p results > results/results.csv
./generate_report --input-folder results --output results/report.html