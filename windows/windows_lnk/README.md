# windows_lnk

**Parse Windows Shell Link (`.lnk`) files** — [MS-SHLLINK]. Recovers the
target path and its MAC times, the command-line arguments, the drive / volume
it lived on, **the NetBIOS name and MAC address of the machine that created the
shortcut**, and **`$MFT` entry / sequence numbers** from the embedded shell
items.

![`windows_lnk gui` — the shortcut viewer](docs/screenshot.png)

```
windows_lnk *.lnk --csv lnk.csv
windows_lnk "%APPDATA%\Microsoft\Windows\Recent" --csv recent.csv
windows_lnk shortcut.lnk --json shortcut.json
windows_lnk Recent/ --gui
```

Zero third-party dependencies, cross-platform (the `--gui` viewer needs
`tkinter`).

---

## Why `.lnk` files matter

Windows creates a `.lnk` in `…\Recent`, `…\Office\Recent` and elsewhere every
time a user opens a file — so a shortcut is **evidence a file existed and was
accessed**, and it keeps that evidence *after the target is deleted*.

- **Target MAC times** are captured in the header (the target's own
  `$STANDARD_INFORMATION` at the moment the link was written).
- The **TrackerDataBlock** records the creating machine's name and — inside the
  Droid object GUID (a v1 UUID) — the **timestamp and MAC address** of the host
  where the link was first created.
- The **shell items** (`BEEF0004` extension) carry the target's short *and*
  long name and, on Windows 7+, its **`$MFT` entry number and sequence**.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_lnk
pip install -e .
```

---

## Usage

```bash
windows_lnk file.lnk                         # printed summary
windows_lnk *.lnk --csv links.csv            # one row per link
windows_lnk Recent/ --json links.json        # full detail incl. shell items
windows_lnk Recent/ --gui                    # tkinter viewer
```

| Switch | |
|---|---|
| `--csv` / `--json` | output (`--json` keeps every shell item + tracker GUIDs) |
| `--no-recurse` | do not descend into sub-directories |
| `--gui` | open the graphical viewer |

### CSV columns

`source_file`, `target_path`, `target_created_utc`, `target_accessed_utc`,
`target_modified_utc`, `target_size`, `file_attributes`, `arguments`,
`working_dir`, `relative_path`, `name`, `icon_location`, `show_command`,
`drive_type`, `drive_serial`, `volume_label`, `network_share`, `machine_id`,
`mac_address`, `droid_object_created_utc`, `known_folder`,
`shell_item_mft_entry`, `flags`, `warnings`.

Header timestamps are ISO-8601 **UTC**. Shell-item timestamps are DOS
date/time — **local time, no timezone** — so they are emitted without a `Z`.

---

## How it works

```
ShellLinkHeader (76 bytes) : LinkCLSID · LinkFlags · FileAttributes ·
                             target Created/Accessed/Written · size · ShowCmd
   │
LinkTargetIDList  → shell ItemID list
       file/dir entries (0x31/0x32) → short name, DOS modified time
       BEEF0004 extension → long name, created/accessed, $MFT entry + sequence
   │
LinkInfo → VolumeID (drive type, serial, label) · LocalBasePath ·
           CommonNetworkRelativeLink (share name) · CommonPathSuffix
   │
StringData → Name, RelativePath, WorkingDir, Arguments, IconLocation
   │
ExtraData blocks:
   TrackerDataBlock (0xA0000003) → MachineID · Droid{volume,object} ·
        DroidBirth{…}   ; the object GUID (UUID v1) → created time + MAC
   KnownFolderDataBlock (0xA000000B) → KNOWNFOLDERID
   EnvironmentVariableDataBlock (0xA0000001) → target with %VARS%
```

---

## Design choices

- **UTC** for the header times; DOS shell-item times kept as local (documented).
- **Never crash.** A 0-byte / non-`.lnk` file, a malformed shell item, or a
  truncated block is reported and skipped; the rest of the link still parses.
- **Off-host.** Pure binary parsing — no `WScript.Shell`, no `IShellLink`.

---

## Status

Validated against **263 real `.lnk` files** from a live `Recent` folder:
target paths, drive serials, machine ID, MAC address (from the tracker UUID),
and `$MFT` references (present in 196 of them) all extract correctly; the 0-byte
placeholder links are reported as errors, as they should be. Shell-item
coverage is focused on file/directory entries and `BEEF0004`; other item types
are recorded but not deeply decoded.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

12 tests: header fields, `LinkInfo` + `StringData`, the tracker block
(machine ID, MAC from a UUID v1, Droid GUID), shell-item `BEEF0004`
(long name, `$MFT` entry + sequence), DOS date/time, non-`.lnk` handling, and
the CLI (`--csv` / `--json`, directory scan, error reporting).

## License

MIT — see [LICENSE](LICENSE).
