# windows_srum

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse SRUDB.dat (System Resource Usage Monitor).**

Reads the SRUM ESE database — per-application network bytes, process resource
use, energy usage, and push-notification counts, each bucketed by hour — and
optionally joins it with the SOFTWARE hive to resolve interface ids to names.

## Planned scope

- Bundled ESE reader (shared with `windows_esedb`)
- Known table maps: network usage, network connectivity, application resource,
  energy, push notifications
- SID → user, app-id → path, interface-id → name resolution
- One normalised timeline row per app per hour

## Inputs

`C:\Windows\System32\sru\SRUDB.dat` (+ optional SOFTWARE hive).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_esedb`, `windows_webcache`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
