# macos_bt

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Bluetooth paired-device history.**

Reads `com.apple.Bluetooth.plist` and related plists for the inventory of paired
and previously connected Bluetooth devices: name, address, device type, and
last-seen / last-connected timestamps.

## Planned scope

- Parse the `DeviceCache` / `PairedDevices` structures
- Device class → type; vendor from the address OUI (bundled table)
- Timeline of pairings / connections
- CSV / JSON

## Inputs

`/Library/Preferences/com.apple.Bluetooth.plist`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_plist`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
