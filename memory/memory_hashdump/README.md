# memory_hashdump

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Extract local NT password hashes from a memory image (reporting only).**

Locates the SAM and SYSTEM hive data in a Windows memory image and derives the
local account NT hashes for incident-response triage and credential-exposure
assessment. Extraction and reporting only — no cracking.

## Planned scope

- Find SAM / SYSTEM in memory; recover the boot key from `LSA`
- Decrypt the per-user hash records (RC4 / AES depending on build)
- Output: user, RID, LM/NT hash, account flags
- Clear IR-scoped framing in the README and `--help`

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_registry`, `memory_lsasecrets`, `windows_registry`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
