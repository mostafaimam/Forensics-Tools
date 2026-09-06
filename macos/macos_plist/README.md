# macos_plist

**macOS property-list reader.** Loads binary (`bplist00`) and XML plists,
**unwraps `NSKeyedArchiver` graphs** into plain data, converts Apple
timestamps, and flattens everything to CSV or JSON.

![`macos_plist --gui`](docs/screenshot.png)

```
macos_plist com.apple.dock.plist --json dock.json
macos_plist ~/Library/Preferences --csv prefs.csv
macos_plist "com.apple.loginwindow.plist" --key "TALAppsToRelaunchAtLogin[0].BundleID"
macos_plist state.plist --no-unwrap --json raw.json
```

Zero third-party dependencies (the base parse uses the standard-library
`plistlib`), cross-platform — read a macOS image's plists from Windows or Linux.

---

## Why

Half the interesting plists on macOS — the Dock, saved application state,
recent items, the Finder sidebar, `loginwindow` relaunch lists — are
**keyed archives**: a flat `$objects` table wired together with `CF$UID`
references. `plistlib` hands that back verbatim, which is unreadable.
`macos_plist` walks the object graph and rebuilds the
`NSDictionary` / `NSArray` / `NSString` / `NSDate` / `NSData` / `NSUUID` /
`NSURL` structure it encodes.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/macos/macos_plist
pip install -e .
```

---

## Usage

```bash
macos_plist file.plist                       # print the flattened contents
macos_plist file.plist --json out.json       # nested JSON (dates -> ISO UTC)
macos_plist file.plist --csv out.csv         # one row per leaf value
macos_plist dir/ --csv all.csv               # every .plist under dir/
macos_plist file.plist --key "a.b[0].c"      # just one value
macos_plist file.plist --no-unwrap           # leave keyed archives as-is
```

| Switch | |
|---|---|
| `--csv FILE` | flatten to `source_file, format, keyed_archive, key_path, value` |
| `--json FILE` | nested JSON, `NSDate` → ISO-8601 UTC, bytes → base64 |
| `--key PATH` | extract one value; dict keys may contain dots (bundle IDs) |
| `--no-unwrap` | do not resolve `NSKeyedArchiver` (keep `$objects` / `CF$UID`) |
| `--no-recurse` | do not descend into sub-directories |

`key_path` uses `.` between dict keys and `[i]` for array indices. A `--key`
path matches the **longest** dictionary key at each step, so
`com.apple.dock.persistent-apps` resolves even though the key contains dots.

---

## Value handling

| plist / Cocoa type | output |
|---|---|
| `NSDate` / `datetime` | ISO-8601 UTC (`2024-06-01T09:30:00.000000Z`) |
| Cocoa `double` that looks like a timestamp | value + `(~2024-06-01T09:30:00Z)` annotation |
| `NSData` / bytes | `base64:…` (large blobs truncated with a byte count) |
| `NSUUID` | canonical UUID string |
| `NSURL` | `base` + `relative` joined |
| unknown archived class | kept as a dict, references resolved, `$class` recorded |
| reference cycle | broken with a `{"$cycle": <index>}` marker |

---

## How it works

```
bytes → detect  "bplist00" | "<?xml … <plist"
      → plistlib.loads(..., aware_datetime=True)
      → is it {$archiver, $objects, $top}?  → NSKeyedArchiver:
            resolve $top through the $objects table, rebuilding
            NSDictionary / NSArray / NSString / NSDate / … with
            cache + cycle detection
      → flatten to dot/bracket paths  |  json_safe nesting  |  --key lookup
```

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix for every date.
- **Never crash.** A corrupt plist is reported as a row / entry with a
  `parse_error`; a keyed-archive unwrap failure falls back to the raw structure
  with a warning.
- **Off-host.** Pure `plistlib` + graph walking — no macOS, no `PlistBuddy`.

---

## Status

Binary and XML parsing come from the standard library and are well tested
there. The `NSKeyedArchiver` unwrapper is covered by tests using
hand-constructed archives that mirror the real `$objects` / `CF$UID` layout
(dictionaries, arrays, strings, dates, data, UUIDs, cycles, non-`root` tops).
Validation against a broad set of real macOS plists is welcome. `NSKeyedArchiver`
classes beyond the common set are preserved but not specially decoded.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

16 tests: format detection, binary / XML load, corrupt-plist handling, keyed
archive detection + unwrap (arrays, nested dicts, `NSMutableString`, `NSData`,
`NSUUID`, cycles, non-`root` `$top`), Cocoa time conversion, CSV flatten,
`--key`, `--no-unwrap`, and directory scan.

## License

MIT — see [LICENSE](LICENSE).
