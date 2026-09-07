# memory_lsasecrets

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Extract LSA secrets and cached domain credentials (reporting only).**

Recovers LSA secrets (`_SC_*` service account passwords, DPAPI machine keys,
auto-logon passwords) and cached domain-logon verifiers (`MSCACHE`) from a
Windows memory image, for IR credential-exposure assessment. Reporting only.

## Planned scope

- Boot-key recovery; `SECURITY\Policy\Secrets` decryption
- MSCACHEv1 / v2 verifier extraction with metadata (user, domain, last logon)
- Flag reversible secrets (service accounts, DefaultPassword)
- IR-scoped; no offline cracking helpers

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_hashdump`, `memory_registry`, `analysis_dpapi`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
