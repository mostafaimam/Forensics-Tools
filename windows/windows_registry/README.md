# windows_registry

**Offline Windows registry hive (`regf`) parser.** Dump keys and values,
regex-search, run built-in extraction plugins, recover deleted keys, and browse
a hive in a `tkinter` window.

```
windows_registry dump NTUSER.DAT --csv ntuser.csv
windows_registry key SYSTEM "ControlSet001\Services\Tcpip"
windows_registry search SOFTWARE --value-data "mimikatz|cobaltstrike"
windows_registry plugin NTUSER.DAT --plugin userassist,run-keys
windows_registry dump NTUSER.DAT --deleted --csv recovered.csv
windows_registry gui SOFTWARE
```

Works on `NTUSER.DAT`, `UsrClass.dat`, `SOFTWARE`, `SYSTEM`, `SAM`, `SECURITY`,
`Amcache.hve`, and any other `regf` hive. Zero third-party dependencies,
cross-platform.

---

## Install

Requires **Python 3.11+** (the GUI needs `tkinter`; on Linux `apt install python3-tk`).

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/windows/windows_registry
pip install -e .
```

---

## Commands

### `dump` — every key and value

```bash
windows_registry dump NTUSER.DAT --csv out.csv
windows_registry dump SOFTWARE --under "Microsoft\Windows\CurrentVersion" --json cv.json
windows_registry dump NTUSER.DAT --deleted --csv recovered.csv
```

CSV columns: `key_path`, `key_last_written_utc`, `value_name`, `value_type`
(`REG_SZ`, `REG_DWORD`, …), `value_data`, `deleted`. `--deleted` additionally
walks free cells and reports orphan `nk` records.

### `key` — one key

```bash
windows_registry key SYSTEM "Select"
windows_registry key SOFTWARE "Microsoft\Windows\CurrentVersion\Run" --recursive
```

### `search` — regex

```bash
windows_registry search SOFTWARE "powershell.*-enc" --value-data
windows_registry search NTUSER.DAT "\.exe$" --value-name --csv hits.csv
```

Flags: `--key-name`, `--value-name`, `--value-data` (default: all three).

### `plugin` — built-in recipes

```bash
windows_registry --list-plugins
windows_registry plugin SYSTEM --plugin services,usbstor --csv sys
windows_registry plugin NTUSER.DAT               # plugins that match the hive kind
windows_registry plugin SOFTWARE --all           # every plugin, regardless of kind
windows_registry plugin NTUSER.DAT --plugin-dir ./myplugins   # + external plugins
```

Given a hive with no `--plugin`, the tool detects the hive kind (NTUSER,
UsrClass, SOFTWARE, SYSTEM, SAM, SECURITY, Amcache) and runs only the plugins
that apply. ~50 plugins ship built in:

| Hive | Plugins |
|---|---|
| **NTUSER** | `run-keys` `userassist` `recentdocs` `runmru` `typed-paths` `typed-urls` `wordwheelquery` `comdlg32` `muicache` `mountpoints2` `rdp-connections` `network-drives` `office-mru` `feature-usage` `sysinternals` `uninstall-user` |
| **UsrClass** | `shellbags` `muicache` |
| **SOFTWARE** | `os-info` `winlogon` `appinit-dlls` `ifeo` `app-paths` `profilelist` `networklist` `defender-exclusions` `powershell-logging` `taskcache` `shell-folders` |
| **SYSTEM** | `computer-info` `services` `bam` `usbstor` `usb-devices` `network-interfaces` `session-manager` `lsa` `run-on-boot` `terminal-server` `portproxy` `firewall-rules` `print-monitors` `mounted-devices` |
| **SAM** | `sam-users` `sam-groups` |
| **SECURITY** | `policy-secrets` `policy-accounts` `policy-domain` |
| **Amcache** | `amcache-files` `amcache-programs` `amcache-drivers` |

`--list-plugins` prints every id with its hive kind and a one-line description.
With `--csv PREFIX` each plugin writes `PREFIX_<plugin>.csv`.

**External plugins.** `--plugin-dir DIR` (repeatable) executes every non-`_`
`*.py` file in `DIR`. Each file runs with `plugin`, `RegistryHive` and the
`_base` helpers (`ft_to_iso`, `value_text`, `values_dict`, `subkey`,
`first_key`, …) already in its globals:

```python
@plugin("my-artefact", "what it extracts", ("software",))
def my_artefact(hive):
    k = hive.get("Some\\Key\\Path")
    return [{"name": v.name, "data": value_text(k, v.name)} for v in k.values()] if k else []
```

### `gui` — hive browser

```bash
windows_registry gui           # then File → Open
windows_registry gui SOFTWARE
```

A `tkinter` window: expandable key tree on the left, the selected key's values
(name / type / data) on the right.

---

## How it works

```
base block "regf"  → sequence numbers (clean / dirty), last-written time,
                     root cell offset, embedded file name
   │
hive bins "hbin" (every 4096 bytes) → cells
   │
cell (i32 size: negative = allocated, positive = free)
   ├─ nk  key node   → flags, last-written, subkey/value counts + list offsets
   ├─ vk  value      → name, type, data (resident ≤4 bytes, or a data cell,
   │                    or a "db" big-data record split into 16 KiB segments)
   ├─ lf / lh / li / ri  subkey lists (recursively flattened)
   └─ value list     → array of vk offsets
   │
tree walk / path lookup (case-insensitive) / regex search
free-cell scan → orphan nk / vk records  (--deleted)
```

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix; `key_last_written_utc` on every row.
- **Read-only**; the hive is opened `rb`.
- **Never crash.** A malformed cell, an unreadable subkey list, or a bad value
  is skipped; the walk continues.
- **Off-host.** Pure binary parsing — a hive carved from an image is read on
  Linux or macOS.

---

## Status

The core `regf` format (base block, hive bins, `nk` / `vk` / `lf` / `lh` /
`li` / `ri` / `db`, resident and big data, all common `REG_*` types) is
implemented and validated against a real hive. Transaction-log (`.LOG1` /
`.LOG2`) replay for dirty hives lives in `windows_reglog`. Not yet done:
security-descriptor (`sk`) decoding and class-name data. Deep artefact
tooling for ShimCache, Amcache, SRUM and jump lists lives under its own
tools. See the project roadmap.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

14 tests cover the base block, tree walk, path lookup, value decoding
(`REG_SZ`, resident `REG_DWORD`), deleted-key recovery, and every CLI command,
against a hand-assembled hive.

## License

MIT — see [LICENSE](LICENSE).
