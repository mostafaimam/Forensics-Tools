# analysis_fuzzyhash

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Similarity hashing and clustering (CTPH + locality hashes).**

Computes context-triggered piecewise hashes (ssdeep-style) and a TLSH-style
locality hash for a file set, plus `imphash` / rich-header hashes for PEs, and
clusters similar documents and binaries — finding near-duplicates and variant
families that exact hashing misses.

## Planned scope

- Bundled CTPH and TLSH-style implementations (no external libs)
- PE import hash and rich-header hash
- Pairwise similarity scoring; threshold-based clustering with cluster reports
- `--against` a baseline; feeds `analysis_dedupe` / `analysis_gallery`

## Inputs

A directory tree, a file list, or a mounted image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`analysis_dedupe`, `analysis_gallery`, `analysis_kff`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
