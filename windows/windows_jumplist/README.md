# windows_jumplist

**Parse `automaticDestinations-ms` jump lists.** These are OLE2 compound files:
a `DestList` stream holding the **MRU order, per-target last-opened time,
machine name and pin state**, plus one embedded **`.lnk`** per target with the
full Shell Link detail (drive serial, `$MFT` reference, arguments).

```
windows_jumplist *.automaticDestinations-ms --csv jl.csv
windows_jumplist "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" --csv all.csv
windows_jumplist 12dc1ea8e34b5a6.automaticDestinations-ms --json photos.json
```

Jump lists live in
`%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\`. The file name is
`<AppID>.automaticDestinations-ms`; the AppID identifies the application.

Zero third-party dependencies — includes a small OLE2 / [MS-CFB] reader and
vendors the suite's `.lnk` parser, so it installs standalone.

---

## Why

A jump list is the application's own "recent files" list. Unlike the shell's
`Recent` folder it records **how many times** each target was opened and the
**exact last time** it was opened *through that application* — and it keeps the
embedded `.lnk` (with its `$MFT` reference and machine ID) after the target is
gone.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_jumplist
pip install -e .
```

---

## Usage

```bash
windows_jumplist file.automaticDestinations-ms            # printed MRU list
windows_jumplist AutomaticDestinations/ --csv jl.csv      # every list, merged
windows_jumplist file.automaticDestinations-ms --json out.json
windows_jumplist AutomaticDestinations/ --pinned-only --csv pinned.csv
```

| Switch | |
|---|---|
| `--csv` / `--json` | one row per jump-list entry |
| `--pinned-only` | keep only pinned entries |

### CSV columns

`source_file`, `app_id`, `application`, `entry_number`, `mru_position`
(0 = most recently used), `pinned`, `last_used_utc`, `target_path`, `hostname`,
`interaction_count`, and — from the embedded `.lnk` —
`lnk_target_modified_utc`, `lnk_drive_serial`, `lnk_machine_id`,
`lnk_mft_entry` (`entry-sequence`).

All timestamps are ISO-8601 **UTC**.

---

## How it works

```
<AppID>.automaticDestinations-ms   →   OLE2 compound file
   ├─ "DestList" stream
   │      header (version 1 = Win7, 3/4 = Win10) : entry count, pinned count
   │      per entry: NetBIOS name · entry number · last-used FILETIME ·
   │                 pin state · access count · target path (UTF-16LE)
   └─ numbered streams  "1", "2", … (hex)   →   a Shell Link each
          parsed for target path, MAC times, drive serial, machine ID,
          and the $MFT entry / sequence from the BEEF0004 shell item
   │
join on the entry number  →  one row per target, in MRU order
```

The AppID is matched against a built-in table of common applications
(File Explorer, Photos, Word, Edge, Chrome, …); unknown IDs pass through.

---

## Design choices

- **UTC** for all timestamps.
- **Never crash.** A truncated `DestList`, a corrupt embedded `.lnk`, a
  non-OLE file — each is reported and the rest still parses.
- **Off-host.** Pure binary parsing — no `IShellLink`, no OLE COM.

---

## Status

Validated against **92 real jump lists** (5 645 entries, 0 errors): MRU order,
last-used times, target paths, resolved AppIDs, and `$MFT` references (present
in 5 603 of the entries) all extract correctly. The DestList **format
version 4** entry layout is derived from real files and confirmed against the
declared entry count; **version 1** (Windows 7) is implemented from the
documentation and untested. `customDestinations-ms` (a different, non-OLE
format) is on the backlog.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

9 tests: the OLE2 reader (stream enumeration + extraction, non-OLE rejection),
the `DestList` v4 parser, a full end-to-end jump list built from a synthetic
OLE + `DestList` + embedded `.lnk`, a list with no `DestList`, and the CLI
(`--csv` / `--json`, `--pinned-only`, directory scan).

## License

MIT — see [LICENSE](LICENSE).
