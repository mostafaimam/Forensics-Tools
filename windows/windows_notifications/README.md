# windows_notifications

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the notification history (wpndatabase.db / appdb.dat).**

Reads `wpndatabase.db` (SQLite) and legacy `appdb.dat` — the Windows toast /
notification store — recovering notification text, payload XML, originating app
(AUMID), arrival and expiry times: often the only record of a message, email or
alert content.

## Planned scope

- Decode the `Notification` / `NotificationHandler` tables and payload XML
- Resolve AUMID → application; extract toast title / body / attribution
- Recover deleted rows from freelist / WAL
- Per-notification timeline

## Inputs

`%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_timeline`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
