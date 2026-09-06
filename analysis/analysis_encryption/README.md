# analysis_encryption

**Detect encrypted / password-protected files and containers.**

> **Report only.** Nothing here decrypts or cracks anything — it tells you
> *what* is encrypted and *how*, so you can decide where to spend effort.

| Scheme | How it's detected |
|---|---|
| PGP / GnuPG | ASCII armor, or an OpenPGP PKESK / SKESK / SEIP packet |
| age | `age-encryption.org/v1` header |
| OpenSSL | `Salted__` prefix |
| Office (docx/xlsx/pptx, legacy doc/xls) | OLE `EncryptedPackage` stream (agile / standard) |
| PDF | `/Encrypt` dictionary (+ `/V` `/R` algorithm) |
| ZIP | general-purpose flag bit 0, AES extra field `0x9901` |
| RAR 4 / 5 | headers-encrypted flag / encryption header |
| 7-Zip | archive present (header may be AES — password needed to list) |
| BitLocker | `-FVE-FS-` boot signature |
| LUKS 1 / 2 | `LUKS\xba\xbe` header |
| FileVault DMG | `encrcdsa` |
| KeePass | KDBX magic |
| SQLCipher | SQLite extension, no `SQLite format 3` header, page-aligned, high entropy |
| VeraCrypt / TrueCrypt | *no signature* — the entropy fallback: uniformly high entropy, 512-byte aligned, `.tc`/`.hc`/`.vc` |

```
analysis_encryption scan /mnt/evidence --csv encrypted.csv
analysis_encryption scan /cases --include-clear --json all.json
analysis_encryption scan secret.tc
```

`scan` exits **1** if any file is `encrypted` / `password-protected`
(pipeline-friendly). Zero third-party dependencies.

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_encryption
pip install -e .
```

---

## Usage

| Switch | |
|---|---|
| `--min-entropy F` | threshold for the headerless-container fallback (default 7.90) |
| `--include-clear` | also list files with no indication of encryption |
| `--exclude GLOB` | skip matching paths / names |
| `--no-recurse` / `--follow-symlinks` | directory-walk options |
| `--csv` / `--json` | output (`path`, `size`, `verdict`, `scheme`, `detail`, `entropy`, `evidence`) |

**Verdicts**: `encrypted` (content is ciphertext), `password-protected`
(structure readable, password to open), `high-entropy` (looks encrypted, no
positive signature), `clear`.

Entropy is sampled from the head, middle and tail (64 KiB each) — recognised
compressed / media containers are excluded so they don't false-positive.

---

## Status

All the signature checks above and the entropy fallback are covered by the
test suite. Not yet done: legacy `.doc`/`.xls` FIB flag parsing, macOS
keychain / APFS-encrypted volume detection, Adobe / Apple DRM, and confirming
7-Zip / RAR *content* (vs header) encryption. See the
[backlog](../../BACKLOG.md).
