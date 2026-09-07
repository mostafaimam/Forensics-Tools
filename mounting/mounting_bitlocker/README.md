# mounting_bitlocker

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Unlock a BitLocker volume with a supplied key.**

Given a recovery key, external key (`.BEK`), clear key, or startup key, unlocks
a BitLocker-encrypted volume or image and exposes the plaintext volume to the
rest of the suite. The examiner supplies the secret — nothing is cracked.

## Planned scope

- Parse the BitLocker metadata block: FVEK-wrapped VMKs, protector types,
  AES-CBC / AES-XTS mode
- Unwrap the VMK from the supplied protector, derive the FVEK
- Present a decrypted read-only stream / device for `mounting_image`
- Report protector inventory even when no key is supplied

## Inputs

A BitLocker volume / partition image; a recovery password, `.BEK`, or clear-key.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mounting_image`, `mounting_luks`, `analysis_encryption`, `analysis_dpapi`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
