# windows_recycle

**Windows Recycle Bin parser** — recovers what was deleted, when, from where, by
which account, and whether the content is still on disk.

![`windows_recycle --gui`](docs/screenshot.png)

Handles both Recycle Bin generations:

- **Vista and later** — `$Recycle.Bin\<SID>\$I……` metadata files (version 1 and
  the Windows 10/11 version 2 layout), matched to their `$R……` content files.
- **NT 4 / 2000 / XP / 2003** — the `RECYCLER\<SID>\INFO2` (and legacy `INFO`)
  index, matched to `Dc……` content files.

Zero third-party dependencies. Runs anywhere Python 3.11+ runs — parse a
Windows Recycle Bin from Linux or macOS.

```
windows_recycle "C:\$Recycle.Bin" --csv deleted.csv
windows_recycle E:\evidence\collection --json deleted.json
windows_recycle "$IA1B2C3.docx" "D:\dump\INFO2"
```

---

## Install

Requires **Python 3.11 or newer**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_recycle
pip install -e .              # provides the `windows_recycle` command
# or run in place:
python -m windows_recycle --help
```

---

## Usage

```bash
# whole Recycle Bin on a live system (all accounts)
windows_recycle "C:\$Recycle.Bin" --csv out.csv

# a triage collection, an image mount, or any folder — searched recursively
windows_recycle E:\evidence\collection --csv out.csv --json out.json

# one artefact file at a time
windows_recycle "$I7GH2K3.docx"
windows_recycle "C:\RECYCLER\S-1-5-21-...\INFO2"

# only the records that failed to parse
windows_recycle E:\evidence --errors-only
```

| Switch | Effect |
|---|---|
| `--csv FILE` | write an RFC-4180 CSV report (UTF-8 BOM, formula-injection safe) |
| `--json FILE` | write a JSON array report |
| `--jsonl FILE` | write a JSON-lines report (one object per line) |
| `--no-recurse` | do not descend into sub-directories |
| `--include-inactive` | also emit `INFO2` slots marked as removed from the bin |
| `--errors-only` | only show records that failed to parse |
| `-q` / `--quiet` | suppress the console table |

Exit code is `0` on success, `1` if every parsed artefact errored.

---

## Output fields

| Field | Meaning |
|---|---|
| `original_path` | full original path of the deleted file |
| `original_size` | logical size (`$I`) or physical / cluster-rounded size (`INFO2`) in bytes |
| `deleted_utc` | deletion time, ISO-8601 **UTC** with a `Z` suffix (blank if the timestamp was zero) |
| `drive` | drive letter, from the path or the `INFO2` drive-number field |
| `sid` | account SID taken from the parent `<SID>` folder |
| `recycle_id` | the random token shared by `$I……` / `$R……` (or the `INFO2` record index) |
| `index` | `INFO2` record index (the `N` in `Dc<N>`) |
| `content_present` | `yes` if the matching `$R……` / `Dc……` file was found next to the metadata |
| `content_path` / `content_is_dir` | where that content is, and whether it is a folder |
| `active` | `no` for an `INFO2` slot whose ANSI name byte was cleared (removed from the bin) |
| `source_kind` / `format_version` / `source` | provenance of the row |
| `warnings` | non-fatal parsing notes |
| `parse_error` | set only on rows that represent a parse failure |

---

## How it works

```
paths (files or dirs)
  │  walk (recursive by default)
  ▼
classify each file
  ├─ $I……            → parse_i_file       (version 1 / version 2)
  ├─ INFO2 / INFO     → parse_info2_file   (record size 0x320 / 0x118)
  └─ $R…… / Dc……      → content index, keyed by recycle-id / record index
  ▼
for every metadata record
  ├─ SID  ← first "S-1-…" component on the path to the artefact
  ├─ drive ← INFO2 drive number, else the path
  └─ content ← lookup in the content index of the same directory
  ▼
unmatched $R / Dc files → emitted as "orphan content" rows
  ▼
sort by deletion time → CSV / JSON / JSONL / console table
```

### `$I` layout (Vista+)

| offset | size | field |
|---|---|---|
| 0 | 8 | version — `1` (pre-Win10) or `2` (Win10+) |
| 8 | 8 | original file size (logical), little-endian |
| 16 | 8 | deletion time — `FILETIME`, UTC |
| 24 | — | **v1:** 520-byte fixed path (260 UTF-16LE units, NUL-terminated) |
| 24 | 4 | **v2:** path length in UTF-16 code units (incl. NUL) |
| 28 | 2·N | **v2:** original path, UTF-16LE |

### `INFO2` layout (NT/2000/XP/2003)

16-byte header (`version`, unused, unused, `record size` at offset `0x0C`),
then fixed-size records:

| offset | size | field |
|---|---|---|
| `0x000` | 260 | original path, ANSI/OEM (byte 0 zeroed when removed from the bin) |
| `0x104` | 4 | record index |
| `0x108` | 4 | drive number (`0` = `A:`) |
| `0x10C` | 8 | deletion time — `FILETIME`, UTC |
| `0x114` | 4 | physical file size |
| `0x118` | 520 | original path, UTF-16LE (record size `0x320` only) |

---

## Design choices

- **UTC only.** `FILETIME` values are already UTC; output is ISO-8601 with a
  `Z` suffix and microsecond precision. No local-time conversion, ever.
- **Never crash on bad input.** A truncated header, an unknown version, an
  implausible path length, or trailing bytes produce a row with a
  `parse_error` / `warnings` value — the rest of the run continues.
- **Unicode-safe.** Paths are decoded as UTF-16LE / OEM with lenient fallback;
  undecodable bytes are flagged in `warnings` rather than dropped.
- **Spreadsheet-safe CSV.** UTF-8 with BOM, every field quoted, and any cell
  starting with `= + - @` or a control character is apostrophe-prefixed so it
  is not evaluated as a formula.
- **Works off-host.** No Windows APIs are used for parsing, so a Recycle Bin
  carved out of an image can be analysed on any platform.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

18 tests cover the `$I` v1/v2 parsers, the `INFO2` parser, SID extraction,
`$R` / `Dc` content matching, orphan detection, CSV-injection handling, and the
end-to-end CLI.

## License

MIT — see [LICENSE](LICENSE).
