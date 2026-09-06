# analysis_dedupe

**Hash-based deduplication and "distinct files" sets.** Groups files by
content, reports duplicate sets and the reclaimable bytes, writes a
one-representative-per-unique-content list, or diffs a target set against a
baseline to show what is new.

![`analysis_dedupe gui`](docs/screenshot.png)

```
analysis_dedupe scan /cases/evidence --csv files.csv
analysis_dedupe scan /export --distinct-out unique.txt
analysis_dedupe scan /new --against baseline.csv --new-only
```

Zero third-party dependencies.

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_dedupe
pip install -e .
```

---

## Usage

```bash
analysis_dedupe scan PATH... [options]
```

| Switch | |
|---|---|
| `--algo md5\|sha1\|sha256` | content hash (default sha256) |
| `--full` | hash every file (default: only files that share a size with another) |
| `--min-size SIZE` | ignore files below this size (default 1 — skips empties) |
| `--exclude GLOB` | skip matching paths / names (repeatable) |
| `--dupes-only` | only files that have a duplicate |
| `--against HASHSET` | a CSV/JSON of baseline hashes → mark each file `new` / `baseline-hit` |
| `--new-only` | with `--against`, only files not in the baseline |
| `--distinct-out FILE` | write one representative path per unique content |
| `--csv` / `--json` | per-file output (`path`, `size`, `digest`, `group`, `representative`, `duplicate_of`, `status`) |

The **size pre-filter** means a large collection where most files are unique
is hashed cheaply — only size collisions are opened. `--full` or `--against`
force a full hash.

`--against` chains from an `acquisition_collect` manifest, an
`analysis_kff` export, or a previous `analysis_dedupe --csv` — anything with
an `sha256` / `sha1` / `md5` column or key.

---

## Status

Walk + size-prefilter + content grouping, reclaimable-bytes accounting, the
distinct-file list, and the `--against` baseline diff are covered by the test
suite. Not yet done: fuzzy / similarity dedupe (ssdeep-style), and a shared
hash cache with `analysis_kff` / `analysis_report`. See the project roadmap.
