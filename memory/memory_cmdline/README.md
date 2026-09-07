# memory_cmdline

**Process command lines from a Windows RAM dump.** For every process found
by pool-tag scanning, the `_EPROCESS` is walked to its user-space `PEB` and
`_RTL_USER_PROCESS_PARAMETERS` to recover the **full command line**, image
path, current directory, window title and (optionally) the environment
block. The `PEB` pointer offset is discovered heuristically, so **no
per-build symbol profile** is needed.

![`memory_cmdline --gui`](docs/screenshot.png)

```
memory_cmdline MEMORY.DMP
memory_cmdline mem.lime --notable-only --csv suspicious.csv
memory_cmdline mem.raw --process powershell --env
memory_cmdline MEMORY.DMP --grep='http|-enc' --json hits.json
```

Reads raw / LiME / ELF-core / crash-dump images. Pure standard library,
cross-platform.

---

## Why it matters

The command line is the fastest read on what a process was *doing*:

* **Living off the land** - `powershell -nop -w hidden -ep bypass -enc …`,
  `certutil -urlcache -f http://…`, `regsvr32 /s /n /u /i:http://…`,
  `rundll32 javascript:…`, `mshta http://…`, `wmic /node: process call
  create`, `bitsadmin /transfer`, `msbuild proj.xml`. Each is flagged.
* **Masquerading** - a process whose argv[0] name does not match its real
  image (`svhost.exe` running as `svchost.exe`), or an executable running
  from `\Users\`, `\AppData\`, `\Temp\`, `\ProgramData\`, `\Downloads\`.
* **Encoded payloads** - a long base64 blob on the command line, decoded on
  sight for the report.
* **Context** - the working directory and window title often reveal the
  user and the file being acted on; `--env` dumps the environment block
  (proxy settings, injected `PATH`, staging directories).

---

## Flags & severity

| flag | severity |
|---|---|
| `powershell-encoded`, `powershell-download-exec`, `base64-blob` | high |
| `certutil misuse`, `bitsadmin transfer`, `regsvr32 sct/url`, `mshta remote/script`, `wmic remote exec`, `mavinject dll inject`, `msbuild inline task`, `argv0-mismatch` | high |
| `powershell-hidden`, `powershell-bypass`, `url-in-cmdline`, `user-writable-path`, `rundll32 script/ordinal`, most other LOLBins | medium |
| `powershell-noprofile` | low |

`--notable-only` keeps flagged rows; `--min-severity` drops rows below a
threshold; `--grep REGEX` filters on the command-line text.

---

## Output

Default is a readable per-process listing. `--csv` gives
`pid`, `process`, `image_path`, `command_line`, `current_dir`,
`window_title`, `notable`, `severity`, `phys_offset` (UTF-8 BOM,
formula-injection safe). `--json` additionally carries `dll_path`, the
parsed `environment`, and the `resolved` flag.

Processes with **no command line recovered** (`System`, `smss.exe`,
`Registry`, protected processes, or an unreadable PEB) are hidden unless
`--unresolved` is given.

---

## Limitations (v0.1)

* **Windows only.** Linux `/proc/<pid>/cmdline`-from-RAM is separate.
* The command line held in the PEB is what the parent *passed*; a process
  can overwrite it after start (some do, to hide) - malfind / handle /
  string evidence still corroborates.
* If the PEB or its parameter block has been paged out, the row shows just
  the image name (from `_EPROCESS`) and is listed only with `--unresolved`.
* Not yet tested against a real multi-gigabyte dump - synthetic coverage
  only (a hand-built `_EPROCESS` -> PEB -> parameters chain with real page
  tables).
