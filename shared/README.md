# shared/

Canonical copies of the helper modules that are **vendored** (copied) into
each tool's package to keep every tool zero-dependency and self-contained.

| file | what it is |
|------|-----------|
| [`tracelib.py`](tracelib.py) | forensic-output layer: chain-of-custody manifest, input/output hashing, per-row provenance columns, standard warnings, parser-confidence and timestamp-provenance vocabularies, and resource limits |
| [`fuzzlib.py`](fuzzlib.py) | a small deterministic mutation fuzzer for the binary parsers — catches unbounded reads, index errors, hangs and runaway allocation on malformed input |
| [`sync_shared.py`](sync_shared.py) | pushes the canonical helpers into every tool that references them; `--check` mode for CI |
| [`tests/`](tests/) | tests for the canonical copies |

```bash
python shared/sync_shared.py            # copy the canonical helpers to every tool
python shared/sync_shared.py --check    # CI: non-zero exit if any copy is stale
cd shared && python -m pytest -q        # test the canonical copies
```

## What `tracelib` gives every tool

Adopting `tracelib` in a tool's `cli.py` adds, to **every run**:

### 1. A run manifest (chain of custody)

A JSON sidecar written next to the first output as `<output>.manifest.json`
(a text-only run writes `<tool>.<timestamp>.manifest.json` only when
`--case-id` / `--examiner` / `--evidence-id` is set), recording:

- the tool and version, and the **exact command line**
- `--case-id`, `--examiner`, `--evidence-id`, `--notes` (or the
  `TRACELIB_CASE_ID` / `TRACELIB_EXAMINER` / `TRACELIB_EVIDENCE_ID`
  environment variables)
- start and finish time in UTC, plus host / user / Python / platform
- **every input file**: path, size, mtime (UTC) and **SHA-256**
- **every output file**: path, size and **SHA-256** (hashed after writing)
- the run's warnings, and counts of `partial` / `unsupported` / `error`

### 2. Per-row provenance

CSV gains `evidence_source`, `parser_confidence`, `tz_provenance` columns
(and `case_id` / `evidence_id` when set); JSON records gain the same fields.
JSON stays a bare list by default (existing consumers are unaffected) —
`tracelib.write_json(..., envelope=True)` wraps it as
`{"manifest": {...}, "records": [...]}` instead.

`--no-provenance` turns all of this off for quick interactive use.

### 3. Parser-confidence and timestamp-provenance vocabularies

`tracelib.CONFIDENCE` — `high` · `medium` · `low` · `recovered` ·
`heuristic` · `unknown`

`tracelib.TZ_PROVENANCE` — `utc-native` · `assumed-utc` · `local-converted`
· `offset-applied` · `no-timezone` · `unknown`

Each tool passes a sensible default for its parser; a tool that recovers
deleted records or heuristically carves can set a lower confidence on those
specific rows.

### 4. Standard warnings

`ctx.partial(code, msg, loc)` / `ctx.unsupported(...)` / `ctx.error(...)`
replace ad-hoc error strings. They land in the manifest and drive the
summary line (`… 3 partial, 1 unsupported`).

### 5. Resource limits

`ctx.limits.check_paths(paths)` refuses an over-size input;
`ctx.limits.tick()` in a parse loop aborts a runaway (record count /
wall-clock); `--max-input-bytes`, `--max-records`, `--wall-seconds`
override the defaults. Exceeding a limit exits `3`.

## Adopting it in a tool

```python
from mytool import __version__, tracelib
...
def build_parser():
    p = argparse.ArgumentParser(...)
    ...
    tracelib.add_arguments(p)
    return p

def main(argv=None):
    a = build_parser().parse_args(argv)
    ...
    ctx = tracelib.context(a, "mytool", __version__)
    try:
        ctx.limits.check_paths([str(x) for x in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr); return 3
    for x in a.paths:
        ctx.add_input(str(x))

    res = analyze(...)
    for e in res.errors:
        ctx.error("source-error", e)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")

    mpath = ctx.finish(outputs=[a.csv, a.json])
    print(ctx.summary_line(len(rows)), file=sys.stderr)
```

Then run `python shared/sync_shared.py` to drop the module into the package.

## Fuzzing the binary parsers

`fuzzlib.fuzz(parse_fn, seeds, iterations=..., seed=...)` mutates valid seed
inputs (bit flips, truncation, extension, length storms, chunk duplication)
and asserts every call returns or raises an *expected* exception — never
hangs past `per_call_seconds`, never allocates past `max_alloc_mb`. Runs
with a fixed RNG seed so a failure reproduces. `accepts="path"` writes the
mutated bytes to a temp file for parsers that take a path.

```python
from mytool import fuzzlib
from mytool import pcap

def test_fuzz_pcap(tmp_path):
    fuzzlib.fuzz(lambda b: list(pcap.read(b)), [valid_pcap_bytes],
                 iterations=400, seed=1, accepts="path", tmp_path=tmp_path)
```

`test_fuzz.py` is present in `network_pcap`, `network_flows`,
`browser_sessions` and `browser_cache`.

## Status

`tracelib` is adopted in **47 tools** — every parser and analysis tool in
`network/`, `browser/`, `memory/`, `windows/`, `linux/`, `macos/`,
`analysis/` and `recovery/`. The `acquisition_*` tools and `mounting_image`
are deliberately excluded: they already implement chain-of-custody
manifests, `--case` / `--examiner` and streaming hashing by design.

`fuzzlib` is wired into `network_pcap`, `network_flows`, `browser_sessions`
and `browser_cache`.
