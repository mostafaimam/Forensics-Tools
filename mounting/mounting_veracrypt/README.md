# mounting_veracrypt

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Unlock a TrueCrypt / VeraCrypt container or partition with a password.**

Opens a VeraCrypt or legacy TrueCrypt volume with a supplied password (plus
optional PIM and keyfiles), detecting standard and hidden volumes, and exposes
the plaintext for downstream parsing. Password supplied by the examiner — not
brute forced.

## Planned scope

- Try the primary and hidden-volume header slots; identify the KDF / cipher
  cascade
- Derive the header key, decrypt the volume header, validate the magic
- Expose standard or hidden volume as a read-only stream
- Flag the presence of a plausible hidden volume

## Inputs

A VeraCrypt / TrueCrypt file container or partition; password (+ PIM /
keyfiles).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mounting_image`, `analysis_encryption`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
