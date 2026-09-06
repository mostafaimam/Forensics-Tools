# windows_amcache

**Parse `Amcache.hve`** — the Application Compatibility inventory hive. Lists
**executables the system has seen (with their SHA-1)**, **installed programs**,
and **drivers**, each with the key's last-written time.

![`windows_amcache --gui`](docs/screenshot.png)

```
windows_amcache Amcache.hve --csv amcache.csv
windows_amcache Amcache.hve --category file --grep "\\\\temp\\\\|\\.tmp"
windows_amcache Amcache.hve --with-sha1 --json files.json
```

`Amcache.hve` lives at
`C:\Windows\AppCompat\Programs\Amcache.hve`. Reuses the suite's `regf` hive
parser (vendored, so this tool installs standalone). Zero third-party
dependencies, cross-platform.

---

## Why it matters

An `InventoryApplicationFile` entry means the executable **existed** at that
path — a strong presence indicator — and the hive records its **SHA-1**, so you
can hash-match it against threat intel or a known-good set without ever seeing
the file. Driver entries and installed-program entries round out the picture.

As with ShimCache, "in Amcache" is evidence of **presence**, not proof of
execution.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_amcache
pip install -e .
```

---

## Usage

```bash
windows_amcache Amcache.hve --csv out.csv --json out.json
windows_amcache Amcache.hve --category file,driver --csv fd.csv
windows_amcache Amcache.hve --grep "powershell|cmd\.exe|rundll32"
windows_amcache Amcache.hve --with-sha1 --json hashable.json
```

| Switch | |
|---|---|
| `--csv` / `--json` | output |
| `--category file,program,driver` | keep only these record kinds |
| `--grep REGEX` | keep only rows whose path or name matches |
| `--with-sha1` | keep only records that carry a SHA-1 |

### CSV columns

`category`, `name`, `path`, `sha1`, `size`, `publisher`, `product`, `version`,
`program_id`, `link_date`, `install_date`, `driver_company`, `driver_signed`,
`key_last_written_utc`, `key_path`.

---

## Formats

| Layout | Windows | Keys |
|---|---|---|
| **modern** | 10 1607+ | `Root\InventoryApplicationFile`, `Root\InventoryApplication`, `Root\InventoryDriverBinary` (named values: `LowerCaseLongPath`, `FileId`, `Size`, `Publisher`, `ProgramId`, `LinkDate`, …) |
| **legacy** | 8 / 8.1 / early 10 | `Root\File\<volume-guid>\<file-id>` and `Root\Programs\<id>` (numbered values: `15` = path, `0` = product, `6` = size, `101` = SHA-1, `17` = date, …) |

`FileId` / `DriverId` values are `0000` followed by the 40-hex-digit SHA-1; the
`0000` prefix is stripped in output. Date-shaped integers are converted from
`FILETIME` or Unix seconds to ISO-8601 UTC.

---

## How it works

```
Amcache.hve  →  regf hive  →  Root (or nested "Root") subkeys
   ├─ InventoryApplicationFile\*  → file records
   ├─ InventoryApplication\*      → program records
   ├─ InventoryDriverBinary\*     → driver records
   └─ File\<guid>\<id>\*  +  Programs\<id>\*   → legacy records
        │
   named / numbered values → normalised row (path, sha1, publisher, size,
   version, program id, dates) + the key's last-written time
```

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix.
- **Never crash.** A non-hive, a missing `Root`, or a malformed entry is
  reported / skipped.
- **Standalone.** The hive parser is vendored under `windows_amcache/hive/`.

---

## Status

The modern and legacy layouts are implemented from the format documentation and
covered by tests using a hand-built `Amcache.hve` (files with SHA-1, a program,
a driver, and a legacy `File\<guid>` tree). The underlying `regf` parser is the
same one validated against real hives elsewhere in the suite. Validation of the
Amcache value mapping against real hives from several Windows builds is welcome.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

9 tests: modern file / program / driver parsing (incl. SHA-1 normalisation),
the legacy `File\<guid>` format, non-hive handling, and the CLI
(`--csv` / `--json`, `--category`, `--grep`, `--with-sha1`).

## License

MIT — see [LICENSE](LICENSE).
