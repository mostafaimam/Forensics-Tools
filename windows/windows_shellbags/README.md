# windows_shellbags

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Reconstruct the ShellBags folder-access tree.**

Parses `BagMRU` / `Bags` from `UsrClass.dat` and `NTUSER.DAT` into a tree of
folders the user browsed in Explorer, with first- and last-interacted times and
the shell-item type for each node (filesystem, network, MTP, search, control
panel, …).

## Planned scope

- Full shell-item type coverage; embedded $MFT references and MAC times
- Rebuild the parent/child tree from the BagMRU slot numbers
- Per-node first / last / most-recent interaction timestamps
- `tkinter` tree browser; CSV / JSON export

## Inputs

`UsrClass.dat` and `NTUSER.DAT` hives (offline or live).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records
- `--gui` — `tkinter` table / tree viewer (and a self-contained HTML view)

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `windows_lnk`, `windows_jumplist`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
