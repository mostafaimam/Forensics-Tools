# macos_unifiedlog

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the macOS unified log (.tracev3).**

A from-scratch reader for the Apple Unified Logging `.tracev3` files, resolving
format strings and static text from the `uuidtext` and `dsc` shared-cache files
into readable log lines with subsystem, category, process, and activity id. A
large effort and the richest macOS timeline source.

## Planned scope

- Parse the tracev3 chunk / firehose format; catalog and timesync handling
- uuidtext / dsc string resolution; %{public}/%{private} formatting
- Filter by subsystem / category / process / predicate; `--since` / `--until`
- Streaming output for multi-GB log sets

## Inputs

`/var/db/diagnostics/**/*.tracev3` plus `/var/db/uuidtext` and the `dsc` cache.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_fsevents`, `macos_knowledgec`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
