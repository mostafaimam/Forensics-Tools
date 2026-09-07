# windows_webcache

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse WebCacheV01.dat (WinINET history / cookies / cache).**

Reads the ESE `WebCacheV01.dat` used by WinINET — legacy IE and Edge and any
application on the WinINET stack — covering the History, Cookies, Content cache
and DOMStore containers, with URL, access count, and timestamps.

## Planned scope

- ESE reader; enumerate the container table and each container's records
- Decode the entry blobs: URL, filename, access / modified / expiry times
- `--extract` cached response bodies from the Content containers
- Merge into the `browser_history` schema

## Inputs

`%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_esedb`, `browser_history`, `browser_cache`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
