# macos_launchd

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Review LaunchAgents / LaunchDaemons persistence.**

Inventories every launchd job — system and per-user LaunchAgents /
LaunchDaemons, plus `/etc/periodic` and login items — with the program
arguments, run schedule / watch paths, and flags for jobs in user-writable
locations, unsigned binaries, or run-at-load with hidden output.

## Planned scope

- Parse the job plists (binary + XML) via the shared plist reader
- Decode StartInterval / StartCalendarInterval / WatchPaths / KeepAlive
- Flag `/tmp` / `~/Library` execs, RunAtLoad + ProgramArguments to shells, label
  / path mismatch
- Cross-check code signature where a binary is present

## Inputs

A mounted macOS image or live system.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_plist`, `macos_tcc`, `linux_persistence`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
