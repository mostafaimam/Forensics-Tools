# mounting_luks

**Unlock a LUKS1 volume with a passphrase you already have.**

`mounting_luks` parses a LUKS1 header, derives a key-slot key from a
supplied passphrase (PBKDF2), recovers the anti-forensic-split key
material, and verifies it against the master-key digest before
decrypting sectors. The examiner supplies the passphrase; nothing is
brute forced, and there is no password guessing of any kind.

## Subcommands

### `info` — header inventory, no passphrase needed

```
mounting_luks info volume.img
```

Reports the UUID, cipher/mode, hash spec, key size, payload offset, and
every key slot (active/inactive, iteration count, stripe count) — useful
triage even without a passphrase: it tells you which cipher mode is in
play and how many active slots exist to try. A LUKS2 header is detected
and reported (UUID, version) but not unlockable — see Limitations.

### `unlock` — derive and verify the master key

```
mounting_luks unlock volume.img --passphrase 'Hunter2!pass'
```

Runs PBKDF2-HMAC (the slot's own hash spec, salt, and iteration count)
on the passphrase to get a slot key, decrypts the slot's AF-split key
material with AES-CBC-ESSIV, merges it back to a candidate master key
(`af_sha1`), then re-derives PBKDF2-HMAC over that candidate and compares
it to the header's master-key digest — a wrong passphrase is **rejected**,
not silently wrong. Prints the recovered master key as hex (`--json` for
machine consumption).

### `decrypt` — unlock, then decrypt a sector range

```
mounting_luks decrypt volume.img --passphrase 'Hunter2!pass' \
    --data-offset 0x100000 --length 4096 -o decrypted.bin
```

Decrypts `--length` bytes starting at `--data-offset` (both
sector-aligned; defaults to the header's own payload offset) with
AES-CBC-ESSIV, writing the plaintext to `--out`. Feed the result to
`recovery_fs` / `windows_mft` for further analysis.

## Usage

| flag | effect |
|------|--------|
| `unlock`/`decrypt --json` | `{slot, master_key_hex}` |
| `info --csv` / `--json` | key-slot inventory |
| `decrypt --data-offset` | default: the header's own payload offset |

## Why it matters

A LUKS-encrypted disk or container recovered during IR is often
unlockable with a passphrase already in hand (from the user, a password
manager, or documentation) — this gets from "encrypted volume" to
"decrypted sector range" without installing `cryptsetup` or touching the
original media beyond a read-only image.

## Limitations (v0.1)

- **LUKS1 only.** LUKS2 headers (Argon2id KDF, JSON metadata area) are
  detected and their UUID/version reported, but not unlockable in v0.1 —
  see `info`'s output for a LUKS2 image.
- **`cbc-essiv:<hash>` cipher mode only.** `xts-plain64` (common on newer
  LUKS1 volumes with AES-256) and any other cipher/mode combination are
  not supported; `unlock` reports an explicit error naming the
  unsupported mode rather than producing wrong output.
- **Passphrase-only.** There is no equivalent of a recovered raw master
  key or an escrowed key file in v0.1 — only the PBKDF2 key-slot path.
- The AES anti-forensic splitter (`af_sha1`) and ESSIV IV derivation are
  implemented from their documented, standardized algorithms and
  self-tested for round-trip correctness, but this parser has **not been
  byte-verified against a volume actually created by a LUKS-formatting
  tool** — see the tests for the format it is built and verified against.
- No writing / re-encryption, no mounting a decrypted volume as a live
  filesystem — pipe `decrypt`'s output to `recovery_fs` for that.

## Tests

`tests/_synth.py` forges a LUKS1 header, an AF-split and AES-CBC-ESSIV
-encrypted key slot, and an encrypted payload region by running the real
PBKDF2 → AF-split → CBC-ESSIV chain **forward** for a known passphrase
(the same self-consistency approach used by `analysis_dpapi`'s and
`mounting_bitlocker`'s tests). The tests cover header parsing, full
master-key unlock, **wrong-passphrase rejection** and
**tampered-digest rejection**, LUKS2 detection, sector-range decryption,
and the `info` / `unlock` / `decrypt` CLI.

```
cd mounting/mounting_luks && python -m pytest -q
```
