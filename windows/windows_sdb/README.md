# windows_sdb

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse application shim databases (.sdb).**

Reads Application Compatibility shim databases — both the system `sysmain.sdb`
and custom / installed `.sdb` files — and lists the shims, patches and their
target executables, a known persistence and injection vector (`InjectDll`,
`RedirectEXE`, custom patches).

## Planned scope

- Parse the SDB tag/record tree: DATABASE, EXE, MATCHING_FILE, SHIM, PATCH
- Flag dangerous shims: InjectDll, RedirectEXE, DisableNXShowUI, custom PATCH
  blobs
- Resolve custom-DB GUIDs to install time / path from the registry
- `tkinter` viewer; CSV / JSON

## Inputs

`*.sdb` files; the `InstalledSDB` registry key for custom databases.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records
- `--gui` — `tkinter` table / tree viewer (and a self-contained HTML view)

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `windows_amcache`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
