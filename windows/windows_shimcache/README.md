# windows_shimcache

**Parse the Windows AppCompatCache (ShimCache).** Evidence that an executable
was **present** on the system — and, on Windows 7 / 8, that it **executed**.
Each entry carries the target's `$STANDARD_INFORMATION` last-modified time and
its position in the cache (0 = most recently added).

```
windows_shimcache SYSTEM --csv shimcache.csv
windows_shimcache appcompatcache.bin --json out.json
windows_shimcache SYSTEM --grep "\\\\temp\\\\|\\.tmp" --executed-only
windows_shimcache --registry            # the live system
```

Reuses the suite's `regf` hive parser (vendored, so this tool installs
standalone). Zero third-party dependencies, cross-platform for the parse
(`--registry` is Windows-only).

---

## What ShimCache is (and isn't)

The Application Compatibility subsystem records executables it evaluates. An
entry means the file **existed** at that path with that `$SI` modified time.

- **Windows 7 / 8** additionally flag entries that were *executed* — surfaced
  here as the `executed` column and `--executed-only`.
- **Windows 8.1 / 10 / 11** do **not** flag execution. Presence + ordering are
  still strong signals, but "in ShimCache" ≠ "ran".
- The timestamp is the file's **last-modified** time, never an execution time.
- The cache is written to the registry only at **shutdown** (per control set),
  so the most recent entries may live in a non-`CurrentControlSet` set, or not
  be on disk at all until the next clean shutdown.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_shimcache
pip install -e .
```

---

## Usage

Input is a **`SYSTEM` hive** (all control sets are parsed and de-duplicated) or
a **raw `AppCompatCache` value** dumped to a file. `--registry` reads it from
the running machine.

```bash
windows_shimcache SYSTEM SYSTEM.LOG1-recovered --csv out.csv
windows_shimcache /eviidence/SYSTEM --json shimcache.json
windows_shimcache appcompatcache.bin
windows_shimcache --registry --csv live.csv
```

| Switch | |
|---|---|
| `--csv` / `--json` | output |
| `--grep REGEX` | keep only matching paths (case-insensitive) |
| `--executed-only` | Windows 7/8: keep only entries flagged executed |
| `--registry` | read `HKLM\SYSTEM\CurrentControlSet\…\AppCompatCache` live |

### CSV columns

`position`, `last_modified_utc`, `executed` (`yes` / `no` / blank on Win10+),
`path`, `control_set`, `data_size`, `source_file`.

---

## Formats

Detected from the first bytes:

| Signature / header | Windows |
|---|---|
| header `0x30` / `0x34`, `10ts` entry magic | 10 / 11 |
| header `0x80`, `00ts` / `10ts` magic | 8 / 8.1 |
| `0xBADC0FEE` | 7 / 2008 R2 (32- and 64-bit entry layouts) |
| `0xDEADBEEF` | XP / 2003 |

---

## How it works

```
SYSTEM hive → for each ControlSet →
   Control\Session Manager\AppCompatCache : "AppCompatCache" (REG_BINARY)
        │
   detect format from the header
        │
   Windows 10/11 : "10ts" entries → u16 path length, UTF-16LE path,
                    FILETIME (last modified), u32 data size
   Windows 7     : fixed 32/48-byte entry table + a trailing path blob;
                    shim-flags bit 0x2 → executed
        │
   position (0 = newest) · path · last_modified_utc · executed · control_set
```

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix.
- **Never crash.** An unknown signature, a truncated entry, or a value that is
  not a cache is reported and skipped.
- **Standalone.** The hive parser is vendored under `windows_shimcache/hive/`,
  so `pip install` needs nothing else.

---

## Status

Windows 10/11 and Windows 7 are validated: the Windows 10 path is checked
against this machine's **live** `AppCompatCache` (1024 entries, real paths and
`$SI` times), and both are covered by tests using hand-built blobs. Windows 8
and XP layouts are implemented from the format documentation; samples for those
are welcome.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

9 tests: format detection, Windows 10 and Windows 7 parsing (incl. the
`executed` flag), extraction from a synthetic `SYSTEM` hive, bad-signature
handling, and the CLI (`--csv` / `--json`, `--grep`, `--executed-only`).

## License

MIT — see [LICENSE](LICENSE).
