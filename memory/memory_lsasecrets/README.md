# memory_lsasecrets

**Decrypt LSA secrets from a SYSTEM + SECURITY hive pair — no password
needed, reporting only.**

`memory_lsasecrets` derives the SYSTEM hive's boot key exactly like
[`memory_hashdump`](../memory_hashdump/) does, then unwraps
`SECURITY\Policy\PolEKList` with it to get the LSA encryption key, and
uses *that* to decrypt every entry under `SECURITY\Policy\Secrets`.
There is no examiner-supplied secret to "not brute force": the LSA key
is recoverable from the two hives alone, by Windows' own design — the
machine must be able to read these secrets back unattended. Several LSA
secrets decrypt straight back to a **plaintext password**
(service-account credentials, auto-logon), which makes their exposure
more immediately actionable than a SAM hash.

## Usage

```
memory_lsasecrets --system SYSTEM --security SECURITY
memory_lsasecrets --system SYSTEM --security SECURITY --csv secrets.csv
memory_lsasecrets --system SYSTEM --security SECURITY --reversible-only
```

| flag | effect |
|------|--------|
| `--reversible-only` | only `_SC_*` service-account-password secrets |
| `--csv` / `--json` | UTF-8-with-BOM, formula-injection-safe output |

Each row carries both `value_text` (best-effort UTF-16LE/UTF-8 decode,
blank if the secret is binary) and `value_hex` (the raw decrypted
bytes) — a `DPAPI_SYSTEM` machine key is binary and will only populate
`value_hex`; a `_SC_*` service-account password is text and populates
both.

## How it works

1. **Boot key** — identical derivation to `memory_hashdump`: the LSA
   `JD`/`Skew1`/`GBG`/`Data` class-name permutation.
2. **LSA key** — `SECURITY\Policy\PolEKList\(default)` is one AES-CBC
   -encrypted blob (version + key GUID + algorithm + flags + salt +
   ciphertext) keyed by the boot key; decrypting it yields an inner
   payload that itself contains the actual LSA key material.
3. **Each secret** — `SECURITY\Policy\Secrets\<name>\CurrVal\(default)`
   is the *same* blob shape, this time keyed by the LSA key from step 2.
   One decrypt function handles both steps.

## Why it matters

`_SC_*` secrets are literally the plaintext passwords Windows Service
Control Manager needs to log a service on as a specific account —
finding one exposes real, working, often domain-level credentials.
`DPAPI_SYSTEM` is the machine's DPAPI backup key, relevant to
`analysis_dpapi` recovery scenarios that don't have a user password.
`DefaultPassword` is the auto-logon password when one is configured.

## Limitations (v0.1)

- **Takes hive files, not a raw memory image**, despite the category
  name — see `memory_hashdump`'s README for why (full hive-body
  reconstruction from scattered physical memory is a separate, harder
  undertaking than `memory_registry`'s hivelist).
- **Modern (`PolEKList`) scheme only.** Legacy pre-Vista SECURITY hives
  (`PolSecretEncryptionKey`, a DES-X-based scheme) are detected as
  absent and reported, not decrypted, in v0.1.
- **The shared AES-CBC wrapper format (version/GUID/algorithm/flags/
  salt/ciphertext, then an inner length-prefixed secret) is well
  established across public SAM/LSA tooling — high confidence.**
  Extracting the *actual* LSA key material out of the decrypted
  `PolEKList` payload (which offset within that payload holds the key)
  is this project's best-effort reading of community references, not a
  published Microsoft specification, and has **not been byte-verified
  against a real modern SECURITY hive.**
- **No MSCACHE (domain cached-credential verifier) extraction** —
  `SECURITY\Cache` is a separate format not covered in v0.1.
- Cracking is explicitly out of scope; this reports what the system
  itself can already read, nothing more.

## Tests

`tests/_synth.py` hand-builds minimal but valid SYSTEM and SECURITY
`regf` hives and forges a `PolEKList` and per-secret `CurrVal` blob by
running the real AES-CBC wrapper **forward** for a known boot key and
LSA key (the same self-consistency approach used by `memory_hashdump`'s
tests). Tests cover LSA-key derivation (and rejection with a wrong boot
key), secret decryption (and rejection with a wrong LSA key), a full
SYSTEM+SECURITY end-to-end dump (service-account password text decode,
binary `DPAPI_SYSTEM` hex-only output, notability flags), missing
-`PolEKList` warning, and the CLI.

```
cd memory/memory_lsasecrets && python -m pytest -q
```
