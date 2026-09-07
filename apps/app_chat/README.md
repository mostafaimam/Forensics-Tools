# app_chat

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Chat / collaboration app forensics with per-application adapters.**

One tool with per-application adapters — Microsoft Teams (classic IndexedDB
LevelDB + `storage.db`; new Teams `*.db`), Slack (LevelDB + `slack-downloads`),
Signal Desktop (needs a supplied key from `config.json`), WhatsApp Desktop,
Discord, Telegram Desktop (`tdata`, structure only without the passcode).
Output: normalised message rows plus an HTML transcript.

## Planned scope

- Adapters share the LevelDB / SQLite / plist back ends
- Normalised row: app, account, conversation, sender, timestamp, text,
  attachment ref
- Attachment / cache extraction where the format allows
- Per-conversation HTML transcript + CSV / JSON

## Inputs

A desktop app's data directory (or a mobile extraction via `mobile_appcommon`).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_localstorage`, `mobile_appcommon`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
