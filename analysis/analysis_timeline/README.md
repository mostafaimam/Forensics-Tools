# analysis_timeline

**Super-timeline builder and viewer.** Ingest the CSV / JSON output of the
other tools (and generic CSV / JSON logs), normalise every timestamp
to UTC, merge everything into one sorted stream, filter it, and review it — on
the command line, as a self-contained HTML page, or in a desktop window.

![`analysis_timeline gui` — the timeline viewer](docs/screenshot.png)

```
analysis_timeline case/ --csv timeline.csv --html timeline.html
analysis_timeline pf.csv recycle.csv --from 2024-03-01 --to 2024-03-08 --grep chrome
analysis_timeline gui case/
```

Zero third-party dependencies. The HTML viewer needs only a browser; the
desktop window uses the standard-library `tkinter` (on Linux install
`python3-tk`).

---

## Why

Each parser answers one question. An investigation needs them on one axis of
time — *what happened on this host between 09:00 and 10:00* — with the
execution events, the deleted files and the collected-file timestamps
interleaved. `analysis_timeline` is that axis: an open, scriptable, diffable
alternative to a timeline-review GUI.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_timeline
pip install -e .
```

---

## Inputs

Point it at files or directories (searched recursively). Recognised
automatically from their columns:

| Source | Events produced |
|---|---|
| `trace-collect` manifest | `created` / `modified` / `accessed` / `changed` / `collected` per file |
| `trace-recycle` CSV | one `deleted` event per record |
| `trace-prefetch` summary CSV | up to 8 `execution` events + `volume-created`, per prefetch file |
| `trace-prefetch` JSON | `execution` events from `run_times_utc` |
| anything else (CSV / JSON / JSONL) | generic: `--time-field` (repeatable) + `--message-field` |

```bash
# generic application log exported to CSV
analysis_timeline app.csv --time-field ts --message-field message --jsonl out.jsonl

# bare Unix timestamps
analysis_timeline events.csv --time-field epoch --epoch --csv out.csv
```

Timestamps with no timezone are treated as UTC; offsets (`+02:00`, `Z`) are
converted.

---

## Output

| Switch | Result |
|---|---|
| *(none)* | sorted table to the console (first `--max-table` rows) |
| `--csv FILE` | full timeline, RFC-4180, UTF-8 BOM, formula-injection safe |
| `--jsonl FILE` | one JSON object per event (keeps nested `extra`) |
| `--html FILE` | **self-contained HTML viewer** — see below |
| `--open` | open the `--html` file in a browser |
| `--bodyfile FILE` | 3.x bodyfile format (pipe-delimited timeline input) |

### Filters (apply to every output)

| Switch | |
|---|---|
| `--from WHEN` / `--to WHEN` | inclusive time bounds (any recognised format, or epoch) |
| `--grep REGEX` | case-insensitive match on description / tool / source / extra |
| `--type T,T` | keep only these timestamp types (`execution`, `deleted`, …) |
| `--tool T,T` | keep only these source tools |
| `--host NAME` | keep only one host |
| `--dedupe` | collapse identical `(time, type, tool, description)` rows |

---

## The HTML viewer (`--html`)

A single file, no server, no external resources. Open it in any browser:

- click any column header to sort
- full-text box (regex), `from` / `to` datetime pickers, `type` and `tool` menus
- **★ tag** rows you care about; tags persist in that browser (`localStorage`)
- **export view CSV** downloads exactly the rows currently shown

Share the file — it carries its data with it.

---

## The desktop viewer (`analysis_timeline gui`)

```bash
analysis_timeline gui case/            # load a folder
analysis_timeline gui                  # start empty, use "open…"
```

A `tkinter` window with the same sort / filter / facet controls and an
`open…` button to add more sources. If `tkinter` is missing the command says
so and points you at `--html`.

---

## How it works

```
inputs ──► adapter (detect layout by columns)
             │   known trace-* layout → explode every timestamp column
             │   unknown              → generic (--time-field / --message-field)
             ▼
          Event(timestamp_utc, timestamp_type, tool, artifact, host, user,
                description, source_file, source_row, extra)
             │
   filters (time / regex / type / tool / host) ─► sort ─► optional dedupe
             │
   ┌─────────┼─────────┬──────────┐
  CSV      JSONL   HTML viewer  bodyfile / console table
```

Every timestamp becomes its own row, so a Prefetch entry with eight run times
contributes eight points on the timeline, each labelled with its type.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
