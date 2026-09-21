# mounting_veracrypt

**Unlock a VeraCrypt/TrueCrypt volume with a password you already have.**

`mounting_veracrypt` derives a header key from a supplied password
(PBKDF2), AES-XTS-decrypts the volume header, validates it (magic +
CRC-32), extracts the master key, and decrypts sectors with it. The
examiner supplies the password; nothing is brute forced, and there is no
password guessing of any kind.

## Subcommands

### `info` — decrypt and report the header

```
mounting_veracrypt info volume.hc --password 'Hunter2!pass'
```

Tries the password against the primary header (offset 0) and the
hidden-volume header slot immediately after it, reports whether a
hidden volume is present, the volume size, sector size, and the byte
offset where the encrypted data area begins.

### `decrypt` — unlock, then decrypt a sector range

```
mounting_veracrypt decrypt volume.hc --password 'Hunter2!pass' \
    --length 4096 -o decrypted.bin
```

Decrypts `--length` bytes starting at `--data-offset` (sector-aligned;
defaults to the header's own master-key-scope offset) with AES-XTS,
writing the plaintext to `--out`.

## Usage

| flag | effect |
|------|--------|
| `--hash {sha512,sha256}` | PBKDF2 hash (default `sha512`) |
| `--iterations N` | PBKDF2 iteration count — **not stored in the volume**; must match how it was created (default `500000`, VeraCrypt's historical non-system SHA-512 default). Override if unlock fails. |
| `--data-offset` (`decrypt`) | default: the header's own master-key-scope offset |
| `info --json` | `{magic, version, is_hidden, volume_size, master_key_scope_offset, encrypted_area_size, sector_size, flags}` |

Unlike LUKS or BitLocker, a VeraCrypt volume does **not** store its own
PBKDF2 iteration count — it's a property of the VeraCrypt version that
created it. If `--iterations 500000 --hash sha512` doesn't unlock a real
volume, try the hash/iteration combination matching the VeraCrypt
version used to create it.

## Why it matters

A VeraCrypt/TrueCrypt container recovered during IR is often unlockable
with a password already in hand — this gets from "encrypted container"
to "decrypted sector range" without installing VeraCrypt or touching the
original media beyond a read-only image.

## Limitations (v0.1)

- **Single-cipher AES-256-XTS volumes only.** Serpent, Twofish, and any
  cascaded cipher (AES-Twofish, AES-Twofish-Serpent, ...) are not
  supported — the master keydata region is read assuming a single
  32-byte primary key + 32-byte tweak key.
- **No PIM, no keyfiles.** Only a plain password is supported in v0.1.
- **Password-only, no legacy RIPEMD-160.** Only PBKDF2-HMAC-SHA512 and
  -SHA256 are supported as KDFs.
- **The exact VeraCrypt Volume Format header layout is publicly
  specified but has not been byte-verified against a real
  VeraCrypt-created volume in this environment.** The magic-bytes check
  and the header CRC-32 mean a wrong password (or a genuinely different
  header layout) is detected as a decode failure rather than silently
  producing garbage — that password-verification path is high
  confidence. Field-level semantics beyond that (volume size, flags,
  sector size) follow this project's best-effort reading of the
  specification and carry correspondingly lower confidence.
- No writing / re-encryption, no mounting a decrypted volume as a live
  filesystem — pipe `decrypt`'s output to `recovery_fs` for that.

## Tests

`tests/_synth.py` forges a volume header and an encrypted payload region
by running the real PBKDF2 → AES-XTS chain **forward** for a known
password (the same self-consistency approach used by `analysis_dpapi`'s,
`mounting_bitlocker`'s and `mounting_luks`'s tests). The tests cover
header unlock, **wrong-password rejection**, **wrong-iteration-count
rejection**, **tampered-CRC rejection**, the legacy `TRUE` magic, the
SHA-256 KDF path, hidden-volume-size reporting, sector-range decryption,
sector-alignment enforcement, and the `info` / `decrypt` CLI.

```
cd mounting/mounting_veracrypt && python -m pytest -q
```
