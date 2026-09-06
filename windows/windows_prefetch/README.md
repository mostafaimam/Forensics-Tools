# windows_prefetch

**Windows Prefetch (`.pf`) parser** — application execution evidence: what ran,
how many times, when it last ran (and the previous seven times), which volumes
and files it touched.

Handles every Prefetch version:

| Version | Windows | Notes |
|---|---|---|
| 17 | XP / 2003 | one last-run time |
| 23 | Vista / 7 | one last-run time |
| 26 | 8.1 | eight last-run times |
| 30 | 10 | **`MAM` / XPRESS-Huffman compressed**; two sub-layouts |
| 31 | 11 | compressed |

The Windows 10/11 `MAM` compression is decompressed with a **pure-Python
XPRESS-Huffman ([MS-XCA] 2.2) implementation** — no dependencies, no OS calls —
so a Windows 11 Prefetch file carved from an image is readable on Linux or
macOS. On Windows the tool uses `ntdll` `RtlDecompressBufferEx` for speed and
falls back to the Python decoder automatically (`--no-native` forces Python).

```
windows_prefetch C:\Windows\Prefetch --csv pf.csv
windows_prefetch NOTEPAD.EXE-D8414F97.pf --json pf.json
windows_prefetch E:\evidence\collection --files-csv referenced.csv
```

---

## Install

Requires **Python 3.11+**. No third-party packages.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_prefetch
pip install -e .
# or: python -m windows_prefetch --help
```

---

## Usage

```bash
# a whole Prefetch folder (or a triage collection, or an image mount)
windows_prefetch C:\Windows\Prefetch --csv pf.csv --json pf.json

# a single file
windows_prefetch "CHROME.EXE-2E8C3F41.pf"

# every file each executable pulled in, one row per (prefetch, file)
windows_prefetch E:\evidence --files-csv referenced_files.csv

# only files that failed to parse
windows_prefetch E:\evidence --errors-only
```

| Switch | Effect |
|---|---|
| `--csv FILE` | one summary row per prefetch file |
| `--files-csv FILE` | one row per referenced file (`executable, source, referenced_file`) |
| `--json FILE` / `--jsonl FILE` | full detail incl. every referenced file and volume |
| `--no-recurse` | do not search sub-directories |
| `--no-native` | always use the pure-Python decompressor |
| `--errors-only` | only show parse failures |
| `-q` | suppress the console table |

---

## Summary CSV columns

`executable`, `run_count`, `last_run_utc`, `version`, `prefetch_hash`,
`referenced_files` (count), `volume_count`, `run_time_1_utc` … `run_time_8_utc`,
`volume_devices`, `volume_serials`, `volume_created_utc`, `compressed`,
`decompressor`, `source`, `warnings`, `parse_error`.

All timestamps are ISO-8601 **UTC** with a `Z` suffix. CSV is UTF-8 with a BOM
and formula-injection safe.

---

## How it works

```
.pf file
  │
  ├─ "SCCA"  → parse directly (Windows 8.1 and earlier)
  └─ "MAM\x04" → read uncompressed size, XPRESS-Huffman decompress → "SCCA"
                   ├─ Windows:  ntdll RtlDecompressBufferEx  (fast path)
                   └─ anywhere: pure-Python [MS-XCA] 2.2 decoder
  ▼
SCCA header (84 bytes):  version · executable name · prefetch hash · flags
  ▼
file information section (offset 84, version-specific size):
  ├─ filename-strings range        (offset 16..23 - same in every version)
  ├─ volume-information range      (offset 24..35 - same in every version)
  ├─ last-run times   (1 time for v17/23, 8 for v26+; offset by version)
  └─ run count        (offset by version; v30 has two sub-layouts,
                       resolved from the file-information section size)
  ▼
referenced files  →  UTF-16LE NUL-separated list of full device paths
volumes           →  device path · serial number · creation time (FILETIME)
```

### XPRESS-Huffman decoder

Implemented from the [MS-XCA] section 2.2 reference: a per-64 KiB-chunk
256-byte Huffman code-length table (512 four-bit lengths), a 32-bit
MSB-first bit reader refilled with little-endian 16-bit words, and
literal / (offset, length) symbols where a length nibble of 15 pulls one or
three extension bytes straight from the byte stream. Verified in the
test-suite against Windows `RtlCompressBuffer` / `RtlDecompressBufferEx` over
hundreds of fuzzed inputs, single- and multi-chunk.

---

## Design choices

- **UTC only.** `FILETIME` values are UTC; output is ISO-8601 with a `Z`
  suffix. A zero `FILETIME` is emitted as blank, not `1601-01-01`.
- **Never crash.** A bad signature, unknown version, truncated section, or
  failed decompression yields a row with `parse_error` / `warnings`; a
  directory scan continues past it.
- **Off-host.** No Windows APIs are required; the `ntdll` path is a pure
  accelerator with an automatic pure-Python fallback.

---

## Status

`v30` / `v31` (Windows 10/11, including `MAM` compression) are the
test-validated path — byte-accurate synthetic structures plus a real
`RtlCompressBuffer` round-trip. `v17` / `v23` / `v26` layouts are implemented
from the format specification; testing against real samples from those Windows
versions is welcome — please open an issue with a sample if one does not parse.

Known decompressor limitation: pathologically compressible input (e.g. a
multi-hundred-KB run of a single repeated phrase) produced by the *maximum*
compression engine is not handled; real Prefetch data does not reach that
ratio.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
