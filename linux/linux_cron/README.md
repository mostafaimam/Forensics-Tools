# linux_cron

**Scheduled-execution inventory for Linux.** Finds every place a host can run
a command on a schedule and normalises them into one table — with a
plain-language description of *when* each job runs and a heuristic flag for
suspicious entries (download-and-execute, reverse shells, `@reboot`
persistence, world-writable paths, history wiping, …).

![`linux_cron --gui`](docs/screenshot.png)

Sources covered:

| Source | Location |
|---|---|
| system crontab | `/etc/crontab` |
| drop-ins | `/etc/cron.d/*` |
| per-user crontabs | `/var/spool/cron/crontabs/*` (Debian), `/var/spool/cron/*` (RHEL) |
| run-parts dirs | `/etc/cron.{hourly,daily,weekly,monthly}/*` |
| anacron | `/etc/anacrontab` |
| `at` / `batch` | `/var/spool/cron/atjobs/*`, `/var/spool/at/*` |
| systemd timers | `*.timer` units under `/etc/`, `/run/`, `/usr/lib/` systemd dirs (+ the `.service` they trigger, + enabled state) |

Zero third-party dependencies, cross-platform — analyse a Linux image's
schedule from Windows or macOS.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/linux/linux_cron
pip install -e .
```

---

## Usage

```bash
# the live host
linux_cron /

# a mounted image
linux_cron /mnt/evidence --csv cron.csv

# only the jobs that tripped a heuristic
linux_cron --notable-only /mnt/evidence

# one file, type guessed from the path
linux_cron --file /etc/cron.d/mdadm
linux_cron --file /mnt/evidence/etc/systemd/system/suspicious.timer --as timer

# just decode a cron expression
linux_cron --explain '*/5 9-17 * * mon-fri'
#   every 5 minutes between 09:00 and 17:59, on Monday, Tuesday, Wednesday, Thursday, Friday
```

| Switch | |
|---|---|
| `root` | filesystem root to scan (`/` or a mount point) |
| `--file PATH` | parse a single file (repeatable) |
| `--as crontab\|cron.d\|user-crontab\|anacrontab\|at\|timer` | force the `--file` type |
| `--explain EXPR` | describe a 5-field cron expression and exit |
| `--source S,S` | keep only these sources (`systemd-timer`, `cron.d`, …) |
| `--user NAME` | keep only jobs running as this user |
| `--notable-only` | only jobs with at least one suspicious-entry flag |
| `--csv` / `--json` | write output files (CSV is UTF-8-BOM, formula-injection safe) |
| `-q` | no table on stdout |

### Columns

`source`, `run_as`, `schedule` (raw), `when` (plain language), `command`,
`env_path` (the `PATH=` in effect for that crontab), `enabled` (systemd
timers), `notable` (`;`-joined reasons), `file`, `line`, `error`.

---

## How it works

**Cron expressions** — a from-scratch parser for the 5 fields
(`minute hour day-of-month month day-of-week`), plus `@reboot` and the
`@hourly … @yearly` shortcuts. Handles ranges, lists, `*/step`, `a-b/step`,
month/day names, and Sunday as both `0` and `7`. It renders each schedule to a
sentence; day-of-month and day-of-week are reported as an **or** when both are
restricted, matching cron's real behaviour.

**systemd timers** — a small unit-file reader (sections, repeated keys,
continuation lines). For each `*.timer` it reads `OnCalendar` / `OnBootSec` /
`OnUnitActiveSec` / `Persistent`, resolves the triggered unit (explicit
`Unit=` or the matching `.service`), and pulls that service's `ExecStart` and
`User`. Enabled state comes from a `.timer` symlink in a `*.wants` directory.

**`at` jobs** — the spool filename encodes the queue letter, job number and
run time (minutes since the epoch); the body's `# atrun uid=` comment gives the
owner. Shell preamble lines (`umask`, `PATH=…; export PATH`, `cd … || {`) are
stripped to leave the queued command.

**Heuristics** are deliberately conservative pattern matches — they point you
at entries to read, they are not a verdict. Every flag is explained in the
`notable` column.

---

## Design choices

- **UTC only**, ISO-8601. `at` run-times are converted from the spool
  filename.
- **Read-only.** Files are opened for reading; nothing is executed.
- **Never crash.** A malformed crontab line becomes a row with an `error` and
  the scan continues.
- **Off-host.** Point `--file` / `root` at a mounted image; the parser never
  needs the analysis box to be Linux.

---

## Status

All sources above are parsed and covered by the test suite (synthetic
fixtures — the dev box has no Linux cron data, as with `linux_utmp`). Not yet
done: resolving systemd `OnCalendar` to concrete next-run times, `fcron` /
`systemd-cron` generator output, and per-file ownership from an image's inode
metadata (needs a filesystem layer — see `recovery_fs` on the roadmap).
