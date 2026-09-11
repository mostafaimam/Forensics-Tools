# mounting_bitlocker

**Unlock BitLocker with the recovery key you already have.**

`mounting_bitlocker` parses a volume's FVE metadata block and, given the
**48-digit recovery password**, derives the Volume Master Key and Full
Volume Encryption Key, then decrypts sectors with them. The examiner
supplies the key; nothing is brute forced, and there is no password
guessing of any kind.

## Subcommands

### `info` — protector inventory, no key needed

```
mounting_bitlocker info volume.img
```

Reports the volume GUID, encryption method, creation time, and every key
protector present (type, GUID, last-modified) — useful triage even
without a recovery key: it tells you *how many* ways the volume can be
unlocked and whether a recovery password protector exists at all.

### `unlock` — derive and verify the VMK / FVEK

```
mounting_bitlocker unlock volume.img --recovery-password \
    '123456-123456-123456-123456-123456-123456-123456-123456'
```

Runs BitLocker's key-stretching KDF (SHA-256 chained `0x100000` times
with the protector's salt) on the recovery password, AES-CCM-unwraps the
VMK, then unwraps the FVEK with it — the CCM authentication tag means a
wrong password is **rejected**, not silently wrong. Prints both keys as
hex (`--json` for machine consumption).

### `decrypt` — unlock, then decrypt a sector range

```
mounting_bitlocker decrypt volume.img --recovery-password '...' \
    --data-offset 0x100000 --length 4096 -o decrypted.bin
```

Decrypts `--length` bytes starting at `--data-offset` (both
sector-aligned) with AES-XTS (modern volumes) or AES-CBC (legacy,
diffuser-less volumes — see Limitations), writing the plaintext to
`--out`. Point `--data-offset` at whatever byte range you need — an MFT
record, a directory of interest, or the whole volume in chunks — and feed
the result to `recovery_fs` / `windows_mft`.

## Usage

| flag | effect |
|------|--------|
| `--offset OFF` (all subcommands) | byte offset of the FVE metadata block, if not at the start of the image |
| `--iterations N` (`unlock`/`decrypt`) | override the key-stretch iteration count — **testing only**; the real value is always `0x100000` |
| `info --csv` / `--json` | protector inventory |
| `unlock --json` | `{protector_guid, method, vmk_hex, fvek_hex}` |

## Why it matters

A BitLocker recovery key recovered from Active Directory / Intune / a
printed copy is often the fastest way into an encrypted endpoint during
IR — faster than TPM extraction or a live boot. Once the FVEK is in hand,
every sector on the volume is decryptable without touching Windows.

## Limitations (v0.1)

- **Recovery-password protector only.** TPM, `.BEK` external-key files,
  and plain passwords are recognised in the `info` inventory but not
  unlockable in v0.1 — the recovery-password path (the one most commonly
  available in an IR engagement) is implemented end to end.
- **The Elephant diffuser is not implemented.** Volumes using the older
  `AES-CBC + diffuser` algorithm (the pre-Windows-10 default) will unlock
  correctly (VMK/FVEK recovery is unaffected — the diffuser only applies
  to sector data) but `decrypt` will **not** produce correct plaintext for
  them; modern `AES-XTS` and plain `AES-CBC` volumes decrypt correctly.
- **The exact on-disk FVE metadata TLV layout is undocumented by
  Microsoft** and has been reverse-engineered by open-source projects
  over many years; this parser follows that general shape (header, then
  type/length/value entries, a VMK protector nesting a stretch-key salt
  and an AES-CCM-wrapped key, a separate AES-CCM-wrapped FVEK dataset) but
  has **not been byte-verified against a real Windows-written volume** in
  this environment — see the tests for the format it is built and
  verified against.
- Sector tweaks for AES-XTS (and the IV derivation for AES-CBC) use the
  **absolute sector number from the start of the volume**; if a real
  volume numbers them differently the decrypted output would be garbled
  in a way that is easy to notice (structure won't parse) but not
  auto-detected here.
- No writing / re-encryption, no mounting a decrypted volume as a live
  filesystem — pipe `decrypt`'s output to `recovery_fs` for that.

## Tests

`tests/_synth.py` forges an FVE metadata block and an encrypted volume
region by running BitLocker's real key-stretch → AES-CCM → AES-XTS chain
**forward** for a known recovery password (the same self-consistency
approach used by `analysis_dpapi`'s tests). The tests cover the recovery
-password checksum decode, FVE metadata parsing, full VMK/FVEK unlock,
**wrong-password rejection** and **tampered-VMK-tag rejection**, sector
-range decryption, and the `info` / `unlock` / `decrypt` CLI.

```
cd mounting/mounting_bitlocker && python -m pytest -q
```
