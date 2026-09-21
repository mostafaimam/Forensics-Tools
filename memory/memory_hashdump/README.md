# memory_hashdump

**Extract local NT/LM hashes from a SYSTEM + SAM hive pair — no password
needed, reporting only.**

`memory_hashdump` derives the SYSTEM hive's own "boot key" and uses it
to decrypt each local account's stored password hash. Unlike
`mounting_bitlocker` / `mounting_luks` / `mounting_veracrypt`, there is
no examiner-supplied secret here to "not brute force": the boot key is
recoverable from the SYSTEM hive alone, by Windows' own design — the
machine itself must be able to do this unattended at every boot. The
output is the stored hash, not a cracked password; turning a hash into
a plaintext password is a separate step this project does not perform.

## Usage

```
memory_hashdump --system SYSTEM --sam SAM
memory_hashdump --system SYSTEM --sam SAM --csv hashes.csv
memory_hashdump --system SYSTEM --sam SAM --empty-only
```

| flag | effect |
|------|--------|
| `--empty-only` | only accounts with a blank NT hash (no password set) |
| `--csv` / `--json` | UTF-8-with-BOM, formula-injection-safe output |

## How it works

1. **Boot key.** `SYSTEM\<CurrentControlSet>\Control\Lsa\{JD,Skew1,GBG,Data}`
   each have a registry *class* string (a field almost no other tool
   reads) holding 8 hex characters; concatenated and hex-decoded, a
   fixed 16-byte permutation turns that into the boot key.
2. **Hashed boot key.** `SAM\Domains\Account\F`'s revision field
   selects the scheme: revision 2 is the legacy RC4 scheme (MD5 of a
   salt + boot key + fixed constants, used as an RC4 key), revision 3
   is the modern AES scheme (AES-CBC keyed directly by the boot key).
3. **Per-user hash.** Each account's `V` value holds an LM/NT hash
   blob. Legacy (RC4) hashes are RC4-decrypted with a key mixing the
   hashed boot key and the account's RID, then run through two rounds
   of DES keyed from the RID itself — the classic "pwdump-era"
   algorithm. Modern (AES) hashes are one AES-CBC decrypt keyed by the
   hashed boot key with a per-hash salt.
4. **Usernames** come from `SAM\Domains\Account\Users\Names\<username>`
   — each such key's default value has no real data, but its declared
   *type* integer is overloaded to hold the RID directly, which avoids
   needing to decode the `V` value's own (less certain) username field
   at all.

## Why it matters

Local account hashes recovered during IR feed directly into
credential-exposure assessment (pass-the-hash risk, password-reuse
checks against known-compromised-hash lists) without needing anything
from the account holder. A blank NT hash on an enabled account is
itself a finding worth flagging on its own.

## Limitations (v0.1)

- **Takes hive files, not a raw memory image**, despite the category
  name. Reconstructing a full, byte-exact hive body from scattered/paged
  physical memory (as opposed to just locating a hive's header, which
  `memory_registry` already does) is a separate, harder undertaking not
  yet built — extract SYSTEM and SAM first (a mounted image,
  `acquisition_collect`, or a live-registry export) and point this tool
  at the files.
- **Confidence differs sharply by scheme.** The legacy (revision 2,
  RC4 + RID-DES) path is the exact algorithm essentially every public
  SAM-dump tool has implemented identically for two decades — high
  confidence, self-tested against the standard DES and RC4 test
  vectors as well as forward-built synthetic hives. The modern
  (revision 3, AES) path's overall shape (AES-CBC replacing RC4/DES) is
  well established, but **the exact byte offsets of the AES
  sub-structure within the `F` and `V` values are this project's
  best-effort reading of community SAM-parsing references, not a
  published Microsoft specification, and have not been byte-verified
  against a real modern SAM hive.**
- No domain-account (NTDS.dit) support — local SAM accounts only.
- Hash cracking is explicitly out of scope; this reports what the
  system itself stores, nothing more.

## Tests

`tests/_synth.py` hand-builds minimal but valid SYSTEM and SAM `regf`
hives (extending the shared hive-builder pattern with registry
key-"class" support for the boot-key permutation), and forges an `F`
value and per-user `V` values by running the real legacy scheme
**forward** for a known boot key. `memory_hashdump/des.py` is verified
against the official FIPS 46-3 test vector and `rc4.py` against a
standard published test vector before either is used for anything.
Tests cover boot-key derivation (including a missing-Lsa error path),
the legacy hashed-boot-key derivation, a full per-user hash round-trip
(and confirming a wrong RID produces a different, wrong hash), a
full SYSTEM+SAM end-to-end dump (including username resolution and
blank-hash detection), and the CLI.

```
cd memory/memory_hashdump && python -m pytest -q
```
