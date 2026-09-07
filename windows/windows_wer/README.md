# windows_wer

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Windows Error Reporting (.wer) reports.**

Reads WER `.wer` report files and the `ReportArchive` / `ReportQueue` stores:
faulting application, module, exception code, load path, and signature — useful
evidence that a program ran (and crashed), including ones long since deleted.

## Planned scope

- Parse the INI-style key/value `.wer` format and the report metadata
- Faulting path, version, timestamp, exception, loaded modules
- Correlate with `windows_amcache` / `windows_prefetch` execution evidence

## Inputs

`%PROGRAMDATA%\Microsoft\Windows\WER\**` and per-user `WER` folders.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_amcache`, `windows_prefetch`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
