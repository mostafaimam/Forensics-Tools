# windows_sum

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the Microsoft User Access Logs (SUM).**

Reads the User Access Logging databases
(`C:\Windows\System32\LogFiles\SUM\*.mdb`) that record client access to server
roles — user, client IP / device, role, first / last access and access count per
day — a rich lateral-movement source on Windows Server.

## Planned scope

- ESE reader; join `SystemIdentity` GUIDs to role and device names
- Per-user / per-client daily access rows with counts
- Highlight access from unexpected subnets / accounts

## Inputs

`SUM\Current.mdb`, `SystemIdentity.mdb`, `*.mdb` role databases.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_esedb`, `windows_evtx`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
