# memory_pslist

**Enumerate Windows processes from a RAM dump** by **pool-tag scanning**.
Every `Proc` (or `Pro\xe3`, protected-process) pool allocation in physical
memory is a candidate `_EPROCESS`; each is validated heuristically — a
plausible image name, a `CreateTime` FILETIME, a PID — **without a per-build
symbol profile**, so it works on any Windows version and surfaces **hidden**
(unlinked / DKOM) and **already-exited** processes that a live-list walk
misses.

```
memory_pslist MEMORY.DMP
memory_pslist mem.lime --terminated-only --csv exited.csv
memory_pslist mem.raw  --min-confidence medium --json ps.json
```

Zero third-party dependencies (vendors `memory_image`'s loader).

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/memory/memory_pslist
pip install -e .
```

---

## Usage

```bash
memory_pslist mem.lime
#     PID    PPID  NAME                 CONF    CREATE (UTC)          EXIT (UTC)
#     764     596  lsass.exe            high    2026-09-01T08:00:00Z
#    6666     764  mal.exe              medium  2026-09-01T09:00:00Z  2026-09-01T09:01:00Z
```

| Switch | |
|---|---|
| `--running-only` / `--terminated-only` | filter by exit state |
| `--name SUBSTR` | image-name substring filter |
| `--min-confidence low\|medium\|high` | drop weak candidates (default `low`) |
| `--csv` / `--json` | output files |

Columns: `pid`, `ppid`, `name`, `create_time`, `exit_time`, `exited`,
`confidence`, `pool_tag`, `phys_offset`.

**Confidence**: `high` = image name ends `.exe` (or a well-known name) *and* a
CreateTime *and* a PID were found; `medium` = name + one of those; `low` =
weaker. Real processes are usually `medium`/`high`; `low` rows are worth a
look but include noise.

---

## How it works & limits

For each `Proc` pool tag, an 8-aligned window is read and searched for:

1. an `ImageFileName` — a 2–15 char printable run followed by a NUL,
   preferring `.exe` and known system names;
2. the first plausible `CreateTime` FILETIME (2012–2038); the 8 bytes after
   it are the `ExitTime` (`0` → running, a later date → exited);
3. PID-like values (`0 < n < 0x40000`, multiple of 4) near the name.

Because it does **not** use a symbol profile, field offsets are inferred, not
known — so:

- **PID / PPID can be wrong or missing** on layouts far from the assumptions;
  the name, pool tag and exit state are the most reliable columns.
- there are **false positives** (freed pool, cached copies) — `confidence`
  and de-duplication by `(pid, name, create_time)` reduce them.
- a profile-driven list walk (`PsActiveProcessLinks` from
  `PsActiveProcessHead`, using the crash-dump `DirectoryTableBase` for
  virtual→physical translation) is planned as a second, exact method and a
  cross-view diff to flag truly hidden processes.

Linux `task_struct` scanning is a separate future tool.

---

## Status

Pool-tag scanning, the `_EPROCESS` heuristic (name / CreateTime / ExitTime /
PID), FILETIME validation, de-duplication and the filters are covered by the
test suite against synthetic `_EPROCESS`-shaped blobs (the dev box has no
real dumps). See the project roadmap.
