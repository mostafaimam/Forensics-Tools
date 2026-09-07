# analysis_dpapi

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Decrypt Windows DPAPI blobs with supplied secrets (reporting for IR).**

Given the user's master keys plus their password (or the domain DPAPI backup
key), decrypts DPAPI-protected blobs — browser credential / cookie keys,
Credential Manager entries, Wi-Fi keys, scheduled-task credentials. The examiner
supplies the secret; nothing is recovered by guessing.

## Planned scope

- Parse the master-key file; derive the key via the user SHA1 / password or the
  RSA backup key
- Decrypt arbitrary DPAPI blobs; recognise known blob types
- Feed decrypted keys into `browser_cookies` / `browser_logins`
- IR-scoped: no password brute forcing

## Inputs

`%APPDATA%\Microsoft\Protect\<SID>\*` master keys, target blobs, and a password
or backup key.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_cookies`, `browser_logins`, `memory_lsasecrets`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
