# mounting_luks

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Unlock a LUKS1 / LUKS2 volume with a passphrase or keyfile.**

Opens a LUKS-encrypted container or partition using a supplied passphrase or
keyfile and exposes the plaintext volume. Bundles a minimal PBKDF2 / Argon2
implementation so there is no external dependency. Not a password recovery tool.

## Planned scope

- Parse the LUKS1 PHDR and LUKS2 JSON metadata: keyslots, KDF parameters, cipher
  spec, segments
- Derive the key from the supplied secret, decrypt the master key
- Expose an AES-XTS / AES-CBC plaintext read-only stream
- List keyslot / token inventory with no secret supplied

## Inputs

A LUKS1 / LUKS2 partition or container; a passphrase or keyfile.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mounting_image`, `mounting_bitlocker`, `analysis_encryption`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
