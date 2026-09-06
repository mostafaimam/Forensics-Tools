# analysis_kff

**Known File Filter.** Import hash sets into a local index, then classify
files (or a list of hashes) as **known-good** (filter out — OS files,
application installs), **known-bad** / **notable** (alert — malware, IOC
lists, CSAM hash sets), or **unknown** (needs a human).

| Import format | |
|---|---|
| NSRL RDS — text | `NSRLFile.txt` and the "minimal" CSV (`SHA-1,MD5,CRC32,FileName,…`) |
| NSRL RDS — SQLite | modern `RDS_*.db` (`FILE` table with `sha256` / `sha1` / `md5`) |
| Project VIC / CAID | the `{"value":[{"files":[{"MD5":…,"SHA1":…}]}]}` JSON |
| HashKeeper / generic CSV | column sniffing for `md5` / `sha1` / `sha256` |
| plain lists | one hash per line, or `md5:<hex>` / `sha256:<hex>` |

The index is a local **SQLite** database (`~/.local/share/analysis_kff/kff.db`
by default, `--db` or `$ANALYSIS_KFF_DB` to change it) — no server, no
third-party packages.

```
analysis_kff import NSRLFile.txt   --name nsrl-2024 --category known-good
analysis_kff import apt-iocs.txt   --name apt41     --category known-bad
analysis_kff scan /mnt/evidence/Users --ignore-known --csv triage.csv
analysis_kff scan /mnt/evidence      --alerts-only  --csv hits.csv
analysis_kff lookup 44d88612fea8a8f36de82e1278abb02f
```

---

## Install

Requires **Python 3.11+** (`sqlite3` is part of the standard library).

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_kff
pip install -e .
```

---

## Usage

### Build the index

```bash
analysis_kff import current/minimal/NSRLFile.txt --name nsrl-minimal --category known-good
analysis_kff import RDS_2024.09.1_modern.db      --name nsrl-modern  --category known-good
analysis_kff import team-iocs.csv               --name campaign-x    --category known-bad --note "ticket 2026-014"
analysis_kff sets
analysis_kff stats
```

The format is auto-detected; `--format` overrides. `--replace` re-imports a
set with an existing name.

### Classify a target

```bash
# hash every file under a mounted image, drop the known-good noise
analysis_kff scan /mnt/evidence --ignore-known --csv triage.csv

# only the alerts (known-bad / notable)
analysis_kff scan /mnt/evidence/Users/bob/Downloads --alerts-only

# classify hashes you already have (e.g. an acquisition_collect manifest,
# or windows_amcache / utilities_hash output) - no re-hashing
analysis_kff scan --hash-list manifest.json .
```

`scan` exits **1** if any known-bad / notable file was found, **0** otherwise
— usable in a pipeline. Each row: `path`, `size`, `status`, `set` (which
imported set matched), `matched_algo`, the three hashes, `error`.

| Switch | |
|---|---|
| `--algo md5\|sha1\|sha256` | limit hashing to these algorithms (repeatable) |
| `--hash-list FILE` | classify precomputed hashes from a CSV / JSON instead of hashing files |
| `--ignore-known` | hide known-good matches |
| `--alerts-only` | show only known-bad / notable |
| `--no-recurse` / `--follow-symlinks` | directory-walk options |
| `--csv` / `--json` | output files (CSV is UTF-8-BOM, formula-injection safe) |

### Look up specific hashes

```bash
analysis_kff lookup 44d88612fea8a8f36de82e1278abb02f e1d2... 
```

---

## How it works

- **One index, three categories.** Every hash row links to a named set with a
  category. On lookup, the strongest match wins: **known-bad > notable >
  known-good**, so a file that is in both the NSRL and an IOC list is still
  an alert.
- **Any algorithm.** A set may carry only MD5, or only SHA-1, or all three;
  `scan` computes all three by default and a match on *any* of them
  classifies the file.
- **Bulk import** streams the source in 50k-row batches with SQLite
  synchronous writes disabled, so a full NSRL RDS (100M+ rows) imports
  without holding it all in memory.

---

## Design choices

- **Local & offline.** A SQLite file you can copy between machines; no
  network, no service.
- **Read-only on evidence.** Files are opened `rb` to hash.
- **Deterministic exit code** for automation (`1` = alerts present).
- **UTC**, ISO-8601 import timestamps.

---

## Status

NSRL text + SQLite, Project VIC JSON, generic CSV and plain-list import, the
three-category index, file and hash-list scanning, and the lookup / sets /
stats commands are covered by the test suite. Not yet done: NSRL "unique" vs
"full" set handling, PhotoDNA / robust perceptual hashes (see
`analysis_gallery`), incremental RDS delta imports, and a shared cache so
`analysis_dedupe` / `analysis_report` can reuse the classification. See the
[backlog](../../BACKLOG.md).
