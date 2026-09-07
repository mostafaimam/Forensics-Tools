# mounting_fvde

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Unlock an APFS / CoreStorage FileVault volume with a password or recovery key.**

Decrypts a FileVault-protected APFS volume (or legacy CoreStorage) using a
supplied user password or personal recovery key and exposes the plaintext APFS
container to `recovery_fs`.

## Planned scope

- Parse the APFS keybag / CoreStorage metadata: wrapped VEK / KEK, user records
- Unwrap the volume key from the supplied credential
- Expose a decrypted read-only APFS container
- Report cryptographic-user inventory with no secret supplied

## Inputs

An encrypted APFS / CoreStorage volume image; a user password or recovery key.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`recovery_fs`, `mounting_bitlocker`, `analysis_encryption`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
