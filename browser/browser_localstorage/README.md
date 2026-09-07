# browser_localstorage

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Per-origin Local Storage and IndexedDB key/value data.**

Reads the LevelDB-backed `Local Storage` and IndexedDB stores (with a bundled
minimal LevelDB reader) into per-origin key/value rows — the backing store for
many web apps (webmail, chat, docs) and often the only place their data lands on
disk.

## Planned scope

- Minimal LevelDB: `.ldb` / `.log` records, sequence numbers, tombstones
- Chromium Local Storage key schema (`_<origin>\x00<key>`)
- IndexedDB object-store record decoding (best effort)
- Per-origin CSV / JSON; `--origin` filter

## Inputs

`Local Storage/leveldb`, `IndexedDB/*.leveldb` directories.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`app_chat`, `browser_sessions`, `analysis_search`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
