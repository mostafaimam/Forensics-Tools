# analysis_report

**Bundle tool output into one case report.** Takes the CSV / JSON exports of
the other tools (plus free-form **Markdown notes**) and produces a single
**self-contained HTML** report and a JSON bundle.

```
analysis_report build case.html --title "Case 2026-014" \
    --input timeline.csv --input kff_hits.csv --input encrypted.csv \
    --note findings.md --case 2026-014 --examiner "A. Analyst" \
    --json case_bundle.json
```

Zero third-party dependencies. The HTML has no external assets — one file you
can email or attach to a ticket.

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_report
pip install -e .
```

---

## Usage

| Switch | |
|---|---|
| `--input PATH` (`-i`) | a CSV / JSON / JSONL file, or a directory of them (repeatable) |
| `--note FILE` | a Markdown notes file (repeatable — concatenated) |
| `--title` | report title |
| `--case` / `--evidence` / `--examiner` / `--organization` / `--summary` | case header fields |
| `--max-rows N` | rows rendered per source table (default 500; the full data is in the JSON bundle) |
| `--json FILE` | also write the machine-readable bundle |

### What the report contains

- **Case header** — the metadata fields you pass.
- **Summary cards** — source count, total rows, **alert rows**.
- **Findings & notes** — your Markdown, rendered.
- **One collapsible section per source** — the table, with **alert rows
  highlighted** and auto-opened. The tool is auto-detected from the column
  set (`analysis_timeline`, `analysis_kff`, `analysis_encryption`,
  `memory_pslist`, `linux_syslog`, `windows_evtx`, …).
- **Input manifest** — SHA-256 of every input file.

An "alert row" is any row with a truthy `notable` / `flags` / `verdict` /
`status` / `timestomped` / `deleted` column (e.g. `known-bad`, `encrypted`,
a non-empty `flags`).

---

## Status

CSV / JSON / JSONL ingest, tool auto-detection, alert-row highlighting, the
mini-Markdown renderer, the HTML report and the JSON bundle are covered by
the test suite. Not yet done: an embedded timeline chart, PDF export,
per-source column selection, and pulling straight from an `analysis_timeline`
HTML export. See the roadmap.
