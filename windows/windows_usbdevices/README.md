# windows_usbdevices

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Reconstruct removable-device history.**

Correlates every USB / removable-storage artefact — `USBSTOR`, `USB`, `SCSI`,
`MountedDevices`, `WPDBUSENUM`, `EMDMgmt`, `setupapi.dev.log` — into one row per
device: make / model, serial, first / last connect, removal time, assigned drive
letter, volume GUID, and the user who used it.

## Planned scope

- Join device serial → volume GUID → drive letter → user → timestamps
- First-install time from setupapi; last-removal from the registry
- Distinguish unique devices vs. re-enumerations
- CSV / JSON; feeds `analysis_timeline` / `analysis_report`

## Inputs

SYSTEM / SOFTWARE / NTUSER hives and `C:\Windows\INF\setupapi.dev.log`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `windows_shellbags`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
