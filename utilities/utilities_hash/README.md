# utilities_hash

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Hash a file set / tree / image's files into a manifest.**

Computes one or more digests (MD5 / SHA-1 / SHA-256 / SHA-3 / BLAKE2) over a
directory tree, a file list, or every file inside a mounted image, and writes a
manifest that feeds `analysis_kff` and integrity verification.

## Planned scope

- Streaming multi-digest in a single pass
- Manifest formats: CSV / JSON / plain `hash  path`
- `--verify` a prior manifest; report added / removed / changed
- Optional per-file metadata (size, mtime, mode)

## Inputs

A directory tree, a file list, or a mounted image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`analysis_kff`, `acquisition_image`, `analysis_dedupe`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
