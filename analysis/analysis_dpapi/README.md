# analysis_dpapi

**Decrypt DPAPI — with the secret you already have, not one you guessed.**

DPAPI is how Windows protects per-user secrets at rest: browser cookie /
credential-encryption keys, Credential Manager entries, Wi-Fi PSKs,
scheduled-task passwords, RDP saved credentials. `analysis_dpapi` unwinds
it **given a secret the examiner supplies** — the user's logon password
plus their SID, or a pre-computed SHA-1 of that password. Nothing is brute
forced.

## Subcommands

### `masterkey` — unlock a master-key file

```
analysis_dpapi masterkey "3e1b2c4d-....." \
    --sid S-1-5-21-1111111111-2222222222-3333333333-1001 \
    --password 'Hunter2!pass'
```

Parses `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`, derives the pre-key
(`HMAC-SHA1(SHA1(pwd_utf16le), sid)`), runs PBKDF2-HMAC-SHA512, decrypts
the master key with AES-256-CBC and **verifies its HMAC** — so a wrong
password / SID is rejected, not silently wrong. Emits the 64-byte master
key.

### `blob` — decrypt one DPAPI blob

```
analysis_dpapi blob cookie.blob --masterkey <64-byte-hex>
analysis_dpapi blob cookie.blob --mk-file MK --sid S-... --password P --entropy <hex>
```

Parses the `_CRYPTPROTECT` blob structure, derives the session key from the
master key and the blob salt (`+ --entropy` if the app used it), decrypts
the data, checks the blob signature, and prints the plaintext as hex /
UTF-8 / UTF-16, plus a type guess (`browser os_crypt AES key`, unicode
string, PE payload, …).

### `scan` — a Protect directory + a folder of blobs

```
analysis_dpapi scan "Protect/S-1-5-21-..." --blobs Vault --blobs "Wi-Fi" \
    --sid S-1-5-21-... --password P --json out.json
```

Decrypts every master key the password unlocks, indexes them by GUID, then
decrypts every blob (files, or blobs carved by their provider-GUID magic
from a larger file) that one of those keys covers.

## Feeding other tools

The master key or the decrypted `os_crypt` key feeds `browser_cookies` /
`browser_logins` so their (currently metadata-only) output can include the
decrypted values in an IR context.

## Limitations (v0.1)

- **Modern scheme only.** Windows 7+ master keys (PBKDF2-HMAC-SHA512 +
  AES-256, blob hash `SHA512`) are supported. Legacy XP/Vista master keys
  (SHA-1 + 3DES) and 3DES blobs are recognised and reported but not
  decrypted — a pure-Python 3DES is on the roadmap.
- **No domain backup key.** Decryption via the domain DPAPI backup RSA
  private key (`-pvk` in other tooling) is not implemented; only the
  user-password path.
- **No credential brute forcing** and no attempt to *find* the password —
  by design. If you do not have the password or its hash, this tool cannot
  help.
- The bundled AES is a compact pure-Python CBC/ECB implementation
  (verified against a NIST vector); it is correctness-first, not fast —
  fine for master keys and blobs, not for bulk data.
- `CredHist` chain walking (using an older password to unlock an older
  master key) is not implemented.

## Tests

`tests/_synth.py` forges a master-key file and DPAPI blobs by running the
real key schedule forward for a known password + SID. The tests cover the
AES round-trip and a NIST ECB vector, master-key decryption + **wrong
password / wrong SID rejection** + the SHA-1-prekey path, blob decryption
with signature verification, blob entropy handling, and the `scan` /
`masterkey` / `blob` CLI with JSON output.

```
cd analysis/analysis_dpapi && python -m pytest -q
```
