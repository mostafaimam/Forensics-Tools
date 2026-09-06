# trace-collect

**Cross-platform targeted forensic triage collector** — an open-source,
zero-dependency artefact-collection tool with a concise command-line interface.

trace-collect walks a set of declarative **targets** (what to collect), pulls the
matching files off a live system or a mounted image, hashes every byte on the
way past, preserves the original timestamps, and writes a full chain-of-custody
manifest.

```
trace-collect --list-targets
trace-collect -d E:\evidence --category EventLogs,Registry --backend vss
trace-collect -d /evidence --source /mnt/image_c --os windows --container zip
```

---

## Why another collector?

Triage collection today is dominated by closed-source, Windows-only tooling.
A collection is the first step of nearly every investigation and feeds every
downstream artefact parser, so an open, cross-platform, auditable collector is
a good foundation to build a suite on.

Known pain points in the existing tooling that trace-collect sets out to fix:

| Pain point | trace-collect's approach |
|---|---|
| Windows `MAX_PATH` (260 char) failures | every absolute path is opened through the `\\?\` extended-length prefix |
| Locked system files (`$MFT`, hives, `*.evtx`) | Windows backup-semantics fallback, plus a real **Volume Shadow Copy** backend (`--backend vss`) |
| No native Linux/macOS collection | first-class `linux` / `macos` target sets |
| Local vs UTC timestamp confusion | **all** timestamps are ISO-8601 UTC with a `Z` suffix, everywhere |
| CSV mangled by Excel / CSV-injection | manifest is UTF-8-BOM, RFC-4180 quoted, formula-injection neutralised |
| Runtime and anti-virus friction of single-file compiled binaries | pure Python 3.11+, standard library only |
| Opaque target formats | targets are plain TOML, validated on load, easy to diff and extend |

---

## Install

Requires **Python 3.11 or newer**. No third-party packages.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/trace-collect
pip install -e .            # provides the `trace-collect` command
# or just run it in place:
python -m trace_collect --help
```

For field use, copy the `trace_collect/` package folder next to a portable Python
and run `python -m trace_collect`.

---

## Usage

### Discover targets

```bash
trace-collect --list-targets                 # targets for THIS operating system
trace-collect --list-targets --all-os        # every built-in target
trace-collect --target-info windows-prefetch # show the exact paths a target expands to
```

### Collect from the live system

```bash
# everything applicable to this OS, into a folder tree
trace-collect -d E:\evidence

# just a few categories, into a single zip, with MD5 + SHA-256
trace-collect -d E:\evidence --category EventLogs,Registry,ProgramExecution \
          --container zip --hash md5,sha256

# specific targets only
trace-collect -d E:\evidence --targets windows-mft,windows-eventlogs --backend vss
```

### Collect locked volume metadata (`$MFT`, in-use hives, `$UsnJrnl`)

Run the console **as Administrator**, then:

```bash
trace-collect -d E:\evidence --category FileSystem,Registry --backend vss
```

`--backend vss` creates a temporary *ClientAccessible* shadow copy per volume,
reads from the snapshot, and deletes the snapshot when finished.

### Collect from a mounted image / another volume

```bash
# image mounted read-only at F:\ with your image-mounting tool of choice
trace-collect -d E:\evidence --source F:\ --os windows

# Linux image mounted at /mnt/evidence
trace-collect -d /cases/001 --source /mnt/evidence --os linux
```

### Useful switches

| Switch | Effect |
|---|---|
| `--dry-run` | enumerate + log + count, copy nothing |
| `--max-size 500MB` | skip files larger than a threshold (logged to the error CSV) |
| `--no-dedupe` | collect a file again even if another target already grabbed it |
| `--follow-symlinks` | follow symlinks / reparse points (off by default — avoids loops) |
| `--target-dir DIR` | load extra `*.toml` target definitions (repeatable) |
| `--examiner NAME` / `--case REF` | recorded in `trace-collect_runinfo.json` |
| `-v` / `-q` | verbose / quiet console |

---

## Output layout

```
<dest>/trace-collect_<host>_<UTC-timestamp>/
├── collection/                     (or collection.zip with --container zip)
│   └── <host>/<volume>/<original directory tree>/...
├── trace-collect_manifest.csv          one row per collected file (see below)
├── trace-collect_errors.csv            every file that could not be collected + why
├── trace-collect_runinfo.json          machine-readable run metadata
├── trace-collect_summary.txt           human-readable summary
└── trace-collect_console.log           full console transcript (UTC)
```

### `trace-collect_manifest.csv` columns

`target_id`, `target_name`, `category`, `source_path`, `output_path`,
`size_bytes`, `backend`, `locked_fallback`, `md5`, `sha1`, `sha256`,
`created_utc`, `modified_utc`, `accessed_utc`, `changed_utc`, `collected_utc`

`locked_fallback = yes` means the file was in use and had to be read via the
Windows backup-semantics path rather than a normal open.

---

## How it works

```
targets (*.toml)                      ┌──────────────┐
  │  id / os / category               │  Reader      │  live  → open(), with a
  │  [[paths]] with %VARS% + globs     │  backend     │          Windows backup-
  ▼                                    │              │          semantics retry
HostContext ──expand_path()──►  concrete paths   ─►  │  vss   → temp shadow copy,
  %SystemDrive% %SystemRoot%           │              │          read from snapshot
  %ProgramData% %Users%                │              │  (image → planned)
  %UserProfiles% / %Home%  (fan-out)   └──────┬───────┘
                                              ▼
                              Collector: enumerate → stat → size-gate → dedupe
                                              ▼
                     stream in 1 MiB chunks ──► MultiHasher (md5/sha1/sha256)
                                              └► Sink (DirSink | ZipSink)
                                              ▼
                              Report: manifest.csv + errors.csv + summary + runinfo
```

1. **Targets** are TOML files under `trace_collect/targets/` (plus any
   `--target-dir`). Each declares an `id`, applicable `os` list, a `category`,
   and one or more `[[paths]]`. A path may contain `%VARIABLES%` and the glob
   wildcards `*`, `?`, `**`. `needs_raw = true` flags targets that only work via
   `--backend vss`.

2. **`HostContext`** resolves the variables from the running system — or, with
   `--source`, re-bases every variable and literal path under the mounted image
   root. `%UserProfiles%` (Windows) and `%Home%` (Linux/macOS) **fan out**: one
   path spec becomes one concrete path per real user profile, so per-user
   artefacts are collected for every account.

3. The **Reader backend** abstracts *how* bytes are obtained:
   - `LiveReader` — normal `open()`, with an automatic `CreateFileW` +
     `FILE_SHARE_READ|WRITE|DELETE` + `FILE_FLAG_BACKUP_SEMANTICS` retry on
     Windows sharing violations.
   - `VssReader` — Windows only; creates a `Win32_ShadowCopy`, maps its
     `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\…` device, reads locked
     volume metadata consistently, and removes every snapshot on exit.
   - `ImageReader` (raw `dd` / E01) — planned, slots in behind the same
     interface.

4. The **Collector** expands each target, enumerates candidate files (glob,
   directory walk for `recursive = true`), applies the `--max-size` gate and
   cross-target de-duplication, then streams each file in 1 MiB chunks
   simultaneously into the hasher and the sink.

5. The **Sink** is either a directory tree (`DirSink`, timestamps restored with
   `os.utime`) or a single Zip64 archive (`ZipSink`, mtime stored in the Zip
   entry). Output paths mirror `<host>/<volume>/<original path>`; the illegal
   `:` in NTFS alternate-data-stream names becomes `__`.

6. The **Report** writes the manifest and error CSVs incrementally (flushed per
   row, so a crash still leaves a usable record) and a final summary.

---

## Writing your own target

```toml
# my_targets/edr.toml   →   trace-collect --target-dir my_targets ...
[[target]]
id          = "crowdstrike-logs"
name        = "CrowdStrike Falcon sensor logs"
description = "Sensor telemetry and update logs"
category    = "EDR"
os          = ["windows"]

[[paths]]
path      = '%SystemDrive%\Windows\System32\drivers\CrowdStrike'
recursive = true

[[paths]]
path = '%ProgramData%\CrowdStrike\*.log'
```

Target files are validated on load — a bad `os` value, a missing `path`, or a
duplicate `id` fails fast with a clear message.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

The suite builds a synthetic source tree, collects it via the real CLI, and
verifies the manifest, hashes, long-path handling, zip output, `--max-size`
gate, and `--dry-run`.

---

## Roadmap

- `ImageReader` — collect directly from raw / E01 disk images without mounting
- SFTP / SMB / S3 push of the finished collection
- `--sha1-manifest` sidecar and detached signing of the manifest
- Optional native NTFS parser so `$MFT` / `$J` work without VSS or admin
- More target packs (EDR products, server roles, container runtimes)

## License

MIT — see [LICENSE](LICENSE).
