# windows_mft

**NTFS `$MFT` and `$UsnJrnl:$J` parser.** Full file-system timeline, alternate
data stream listing, and `$SI` vs `$FN` timestamp-anomaly (timestomping)
detection — from an extracted `$MFT`, an NTFS volume image, or a disk image
with `--offset`.

```
windows_mft mft  \$MFT --csv mft.csv
windows_mft mft  volume.raw --offset 1048576 --timestomped-only --csv suspicious.csv
windows_mft usn  \$J --csv usn.csv --reason FILE_DELETE,RENAME_OLD_NAME
windows_mft cat  volume.raw --entry 5312 --stream Zone.Identifier
windows_mft gui
```

Zero third-party dependencies, cross-platform. The GUI uses the standard-library
`tkinter` (on Linux install `python3-tk`).

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_mft
pip install -e .
```

---

## `mft` — parse the Master File Table

Accepts a **bare extracted `$MFT`** file (no boot sector — resident attributes
only, which is all timeline analysis needs) *or* an **NTFS volume / disk image**
(`--offset` bytes to the partition; non-resident content and `cat` then work
too).

```bash
windows_mft mft "$MFT" --csv mft.csv --json mft.json --bodyfile bodyfile
windows_mft mft image.raw --offset 1048576 --deleted-only --files-only
windows_mft mft "$MFT" --timestomped-only --csv timestomped.csv
```

| Switch | |
|---|---|
| `--csv` / `--json` | full listing |
| `--bodyfile` | TSK 3.x bodyfile built from the `$SI` timestamps |
| `--deleted-only` | records whose in-use flag is clear |
| `--files-only` | skip directories |
| `--timestomped-only` | only entries with a timestamp anomaly |
| `--no-system` | skip reserved system files (entries 0-15) |
| `--offset N` | byte offset of the NTFS volume in the image |

### CSV columns

`entry`, `sequence`, `state` (allocated / deleted), `type`, `path`, `name`,
`extension`, `parent_entry`, `logical_size`, `hard_links`, `is_resident`,
`has_ads`, `ads_names`, `fixup_ok`, and the eight timestamps
`si_{created,modified,mft_modified,accessed}_utc` +
`fn_{created,modified,mft_modified,accessed}_utc` (ISO-8601 UTC), plus
`timestomp` and `timestomp_reasons`.

### Timestomp detection

`timestomp = yes` when either:

- a **strong** signal — `$SI` created earlier than `$FN` created, or `$FN`
  modified newer than `$SI` modified (the `$FN` timestamps are far harder for
  an attacker to alter); or
- the classic weak pattern — **all four `$SI` timestamps identical *and*
  second-aligned** (zero sub-second precision), which is what timestamp-editing
  tools produce and genuine NTFS activity almost never does.

`timestomp_reasons` spells out which fired.

---

## `usn` — parse the change journal

Point it at an extracted `$Extend\$UsnJrnl:$J` data stream. Sparse NUL runs
between records are skipped; `USN_RECORD` v2 and v3 are both handled.

```bash
windows_mft usn "$J" --csv usn.csv
windows_mft usn "$J" --json usn.json --reason FILE_CREATE,FILE_DELETE
```

CSV columns: `usn`, `timestamp_utc`, `file_entry`, `file_sequence`,
`parent_entry`, `name`, `reasons` (decoded flag names), `source_info`,
`file_attributes`.

---

## `cat` — extract one data stream

```bash
windows_mft cat volume.raw --entry 5312                       # default $DATA
windows_mft cat volume.raw --entry 5312 --stream Zone.Identifier
```

Needs a volume/image (not a bare `$MFT`) for non-resident streams.

---

## `gui` — graphical `$MFT` browser

```bash
windows_mft gui
```

A `tkinter` window: open an extracted `$MFT` or an image, browse the directory
tree (deleted entries and timestomped entries flagged), and see every attribute
of the selected entry — both timestamp sets, all `$FILE_NAME` names, every data
stream, and the timestomp reasons — in a detail pane.

---

## How it works

```
source
  ├─ NTFS volume/image → boot sector → $MFT record 0 → non-resident $DATA
  │                       run list → full (fragmented) MFT extent
  └─ bare $MFT file     → record size detected from the first FILE record
        │
per 1 KiB record:
  ├─ update-sequence-array fixup (verified; fixup_ok=no on mismatch)
  ├─ flags → in-use? directory?   base record reference
  ├─ $STANDARD_INFORMATION  → C/M/R/A FILETIMEs
  ├─ $FILE_NAME × N (Win32 namespace preferred) → name, parent, $FN C/M/R/A
  └─ $DATA × N → unnamed stream size + every named stream (ADS)
        │
parent-entry chain → full path       $SI/$FN comparison → timestomp flags
        │
CSV / JSON / bodyfile / console table         (usn: separate USN_RECORD parser)
```

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix; zero `FILETIME` → blank.
- **Read-only**; the source is opened `rb`.
- **Never crash.** A bad signature, failed fixup, or malformed attribute skips
  that record (flagged where visible) and the walk continues.
- **Off-host.** No Windows APIs — a `$MFT` pulled from any image is parsed on
  Linux or macOS identically.

---

## Status

Validated against a hand-built, byte-accurate synthetic NTFS image (resident
file + ADS, deleted non-resident file, sub-directory path resolution,
timestomped file, fixup verification, run-list decode) and crafted
`USN_RECORD` v2 data with a sparse gap. Real-image testing is welcome.
`$ATTRIBUTE_LIST` (heavily fragmented files), `$SDS` security descriptors,
`$Boot`, and `$LogFile` are on the backlog.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
