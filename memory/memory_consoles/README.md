# memory_consoles

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Reconstruct console / conhost screen and command history buffers.**

Recovers interactive console state from a Windows memory image — the
`conhost.exe` screen buffer (visible + scrollback text) and the
`COMMAND_HISTORY` / alias buffers per attached process — exposing attacker
keystrokes and command output.

## Planned scope

- Scan `conhost` for `_CONSOLE_INFORMATION` / screen-buffer structures
  (version-gated offsets)
- Rebuild the character grid into readable lines
- Extract `COMMAND_HISTORY` entries with the owning process image
- Flag encoded commands / download cradles in the recovered text

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_cmdline`, `memory_pslist`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
