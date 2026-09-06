# windows_evtx

**Windows event log (`.evtx`) parser.** A from-scratch binary + BinXml reader
that turns event logs into a standardised CSV, JSON / JSONL, or XML — with
event-ID, provider, channel, level and time-range filters.

```
windows_evtx Security.evtx --csv security.csv
windows_evtx System.evtx --event-id 7045,7040 --json services.json
windows_evtx C:\evidence\Logs --from 2024-03-01 --to 2024-03-08 --csv week.csv
```

Zero third-party dependencies, cross-platform — parse a `.evtx` carved from a
disk image on Linux or macOS just the same.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_evtx
pip install -e .
```

---

## Usage

```bash
windows_evtx App.evtx Sys.evtx --csv out.csv          # several files at once
windows_evtx C:\Windows\System32\winevt\Logs --csv all.csv   # a directory
windows_evtx Security.evtx --provider Microsoft-Windows-Security-Auditing \
             --event-id 4624,4625 --level Error,Warning --jsonl logons.jsonl
windows_evtx System.evtx --xml system.xml
```

| Switch | |
|---|---|
| `--csv` / `--json` / `--jsonl` / `--xml` | output formats (combine freely) |
| `--event-id ID,ID` | keep only these event IDs |
| `--provider NAME,NAME` | keep only these providers (case-insensitive) |
| `--channel NAME,NAME` | keep only these channels |
| `--level Error,Warning` | keep only these rendered levels |
| `--from WHEN` / `--to WHEN` | inclusive `TimeCreated` bounds |
| `--errors-only` | only records that failed to parse |
| `-q` | suppress the console table |

Records are sorted by `TimeCreated`. Exit code is `0` on success, `2` if no
`.evtx` file could be opened.

---

## Standardised CSV

One row per event:

`RecordNumber`, `TimeCreated`, `EventId`, `Level`, `Provider`, `Channel`,
`Computer`, `UserId` (SID), `MapDescription`, `ChunkNumber`, `Task`, `Opcode`,
`Keywords`, `ProcessId`, `ThreadId`, `ActivityId`,
`PayloadData1`…`PayloadData6` (the first six `EventData` / `UserData` fields as
`name: value`), `Payload` (the full data block as JSON), `SourceFile`,
`ParseError`.

All timestamps are ISO-8601 **UTC** with a `Z` suffix. The CSV is UTF-8 with a
BOM and formula-injection safe. `--json` / `--jsonl` additionally carry the
full rendered **XML** and the complete data dictionary.

`MapDescription` is reserved for the planned event-ID → friendly-description
maps (see the roadmap); it is empty in v0.1.

---

## How it works

```
file header  "ElfFile\0"  → chunk count, versions, dirty / full flags
   │
each 64 KiB chunk  "ElfChnk\0"  → name-string and template buckets
   │
each event record  magic 0x00002a2a  → record id, written FILETIME, BinXml
   │
BinXml (token stream, parsed against the chunk buffer):
   ├─ name strings & templates referenced by chunk offset (cached per chunk)
   ├─ a template body is parsed once, keeping Sub placeholders, then
   │   re-rendered for every instance with that instance's substitution array
   ├─ 24 value types: wstring/string, (u)int8-64, real, bool, binary, guid,
   │   FILETIME, SystemTime, SID, hex32/64, size_t, and nested BinXml
   └─ arrays (type bit 0x80)
   │
element tree → XML string + extracted System fields + EventData / UserData
```

Validated against real logs exported with the OS event service: a `Setup`
channel (533 records) and an `Application` channel (~41,000 records) both parse
with **zero errors**.

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix.
- **Never crash.** A record whose BinXml fails to parse becomes a row with a
  `ParseError`; the rest of the file continues. Dirty / partially-written logs
  are read as far as they go.
- **No OS dependency.** Pure binary parsing — works off-host on any platform.
- **Faithful.** The rendered XML matches the event-viewer XML view; the
  standardised columns are derived from it, not guessed.

---

## Status

The binary container and the BinXml dialect (templates, substitutions, nested
BinXml, all documented value types, arrays) are implemented and exercised
against real multi-thousand-record logs. Not yet done: event-ID description
**maps**, `wevtutil`-style locale message resolution, recovered records from
chunk slack, and CRC verification. See the backlog.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

11 tests cover the BinXml element / value / template / substitution paths and
the CLI (CSV / JSON / XML, filters, directory input) against hand-assembled
EVTX.

## License

MIT — see [LICENSE](LICENSE).
