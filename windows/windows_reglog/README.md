# windows_reglog

**Replay Windows registry transaction logs (`.LOG1` / `.LOG2`) into a dirty
hive** so downstream tools see a clean, current hive.

```
windows_reglog SYSTEM -o SYSTEM.clean
windows_reglog NTUSER.DAT --log NTUSER.DAT.LOG1 NTUSER.DAT.LOG2 -o out.dat
windows_reglog --info SOFTWARE
```

A hive is *dirty* when its primary and secondary sequence numbers differ — the
last writes live only in the transaction log until the next flush. Parsers that
do not understand logs then miss the most recent changes (or fail outright).
`windows_reglog` applies the outstanding log entries and rewrites the base
block so the hive is clean.

Zero third-party dependencies, cross-platform.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_reglog
pip install -e .
```

---

## Usage

```bash
# auto-find NTUSER.DAT.LOG1 / .LOG2 beside the hive
windows_reglog NTUSER.DAT -o NTUSER.clean.dat

# name the logs explicitly (any order)
windows_reglog SYSTEM --log SYSTEM.LOG1 SYSTEM.LOG2 -o SYSTEM.clean

# inspect without writing anything
windows_reglog --info SOFTWARE
```

| Switch | |
|---|---|
| `-o FILE` | write the recovered hive (without this, nothing is written) |
| `--log LOG …` | transaction log(s); default is to look beside the hive |
| `--info` | show sequence numbers and a per-log entry summary, then exit |
| `--no-verify` | skip Marvin32 hash verification of log entries |
| `-q` | quieter |

An already-clean hive is copied straight through to `-o` unchanged.

---

## How it works

```
primary hive  "regf"  → primary_sequence vs secondary_sequence
   │   equal  → clean, copy through
   │   differ → dirty, replay:
   ▼
transaction log  "regf" (512-byte base block, file type != 0)
   │
each "HvLE" log entry (512-byte aligned):
   ├─ sequence number, hive-bins size after this entry, dirty-page count
   ├─ Marvin32 hash-1 (over the entry body) and hash-2 (over the header)
   │      - verified with the constant registry seed 0x82EF4D887A4E55C5
   └─ dirty-page refs { hbins-relative offset, size } + the page data
   │
apply entries in ascending sequence, starting from secondary_sequence,
   writing each dirty page into  hive[4096 + offset : …]
   │
rewrite base block: primary = secondary = last applied sequence + 1,
   hive-bins size, XOR-32 checksum; trim to base block + hive bins
```

Both the "new format" (Windows 8.1+) HvLE structure and the Marvin32
authentication are implemented. Old-format (Windows 7 and earlier) `DIRT`
logs are detected and reported as unsupported for now.

---

## Design choices

- **Read-only inputs.** The hive and logs are never modified in place; the
  result is written only to `-o`.
- **Verify, but don't stop.** A log entry whose Marvin32 hash does not match is
  reported and still applied (a mismatch usually means a truncated final entry,
  not corruption of the earlier ones); `--no-verify` silences the check.
- **Off-host.** Pure binary work — recover a hive from an image on any platform.

---

## Status

Validated against real Windows transaction logs: the Marvin32 hash-1 and
hash-2 of live `HvLE` entries verify, and a rolled-back, page-corrupted hive is
restored byte-for-byte by replaying its log. Not yet done: old-format (`DIRT`)
logs, and reconciling a log whose entries predate the hive (nothing to do) vs.
a genuine sequence gap (reported and stopped).

---

## Development

```bash
pip install pytest
python -m pytest -q
```

13 tests: the Marvin32 implementation (incl. a real-log test vector), `HvLE`
parsing, contiguous replay, the clean-hive pass-through, and every CLI path
against a hand-assembled hive + log.

## License

MIT — see [LICENSE](LICENSE).
