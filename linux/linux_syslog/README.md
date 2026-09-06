# linux_syslog

**Normaliser for classic Linux text logs.** Reads `syslog` / `messages` /
`auth.log` / `secure` and friends — including rotated `.1` files and `.gz`
archives — understands both the BSD (RFC 3164) and RFC 5424 line formats, and
produces either:

![`linux_syslog --gui`](docs/screenshot.png)

- a **record timeline** — one row per log line, timestamp normalised to UTC,
  with `facility` / `severity` / `tag` / `pid` / `message` split out; or
- a **structured security-event stream** (`--events`) — SSH logins, `sudo`,
  `su`, PAM auth failures, session open/close, cron execution, account
  changes — each as a typed row (`category`, `action`, `result`, `user`,
  `source_ip`, …).

```
linux_syslog /var/log/auth.log --events
linux_syslog /mnt/evidence --root --events --csv events.csv
linux_syslog /var/log/syslog* --severity err,crit,alert
linux_syslog /var/log/auth.log --events --category ssh --result failure
```

Zero third-party dependencies, cross-platform — read a Linux image's logs
from Windows or macOS.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/linux/linux_syslog
pip install -e .
```

---

## Usage

Pass log files directly, or a filesystem root with `--root` (it scans
`var/log` for the known log families and their rotations, oldest first).
`.gz` archives are decompressed transparently; multi-line messages
(stack traces, `iptables` dumps) are folded into the preceding record.

```bash
# every record from one file
linux_syslog /var/log/auth.log --csv records.csv

# merge a whole rotation set
linux_syslog /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz

# structured security events from an image
linux_syslog /mnt/evidence --root --events --csv events.csv

# failed SSH auth from one network
linux_syslog /var/log/auth.log --events --category ssh --result failure --ip 198.51.100.23

# decode a specific window
linux_syslog /var/log/syslog --from 2024-02-10T09:00 --to 2024-02-10T10:00
```

| Switch | |
|---|---|
| `--root` | treat arguments as filesystem roots; scan `var/log` |
| `--events` | emit structured events instead of records |
| `--tz +HH:MM` | timezone of naive BSD timestamps (default UTC; ISO/5424 offsets always honoured) |
| `--year N` | year for BSD timestamps that carry none (default: file mtime year, with December→previous-year roll-back) |
| `--tag` / `--host` / `--severity` / `--facility` | record filters (comma lists) |
| `--grep REGEX` | keep only messages matching (case-insensitive) |
| `--category` / `--result` / `--user` / `--ip` | event filters |
| `--from` / `--to` | inclusive time bounds |
| `--csv` / `--json` | output files (CSV is UTF-8-BOM, formula-injection safe) |
| `-q` | no table on stdout |

### Event categories

| Category | Recognised lines |
|---|---|
| `ssh` | `Accepted` / `Failed` password·publickey, `Invalid user`, `message repeated`, max-auth-attempts, pre-auth disconnects |
| `sudo` | `USER : TTY=… ; COMMAND=…`, incorrect-password attempts, `NOT in sudoers` |
| `su` | `pam_unix(su:auth)` failures, `+ pts/0 user:target` switch lines, `Successful/FAILED su` |
| `session` | `systemd-logind` new/removed sessions, tty `login` |
| `cron` | `CRON` PAM sessions and `(user) CMD (…)` execution |
| `account` | `useradd` / `userdel` / `usermod` / `passwd` / `groupadd` |
| `pam` | generic `pam_unix(<svc>:<phase>)` auth/session results |

---

## How it works

**Line format.** An optional `<PRI>` is decoded to facility + severity. Then
one of: a BSD timestamp (`Feb 10 09:02:11`, no year), an ISO-8601 timestamp
(rsyslog's `FileFormat`, with or without a `±HH:MM` offset), or an RFC 5424
frame (`1 TIMESTAMP HOST APP PROCID MSGID SD MSG`). The host token, then a
`tag[pid]:` prefix, are peeled off the remainder.

**Year inference.** BSD timestamps have no year. The file's mtime year is used;
a line whose date lands more than a day in the future of the mtime is rolled
back a year (a January-dated file still holding December lines). `--year`
overrides.

**Timezone.** BSD timestamps are naive — assumed UTC unless `--tz` says
otherwise. ISO and RFC 5424 offsets are always converted. Output is UTC,
ISO-8601 with a `Z`.

**Events** are matched by `(tag, regex)` rules against the message. A line that
matches nothing is simply not an event — the record is still in the record
view.

---

## Design choices

- **UTC only** in output.
- **Read-only.** Files are opened for reading.
- **Never crash.** An unparseable line becomes a record with `format=unparsed`
  and no timestamp; the run continues.
- **Off-host.** Point `--root` at a mounted image; nothing needs the analysis
  box to be Linux.

---

## Status

BSD / ISO / RFC 5424 line formats and the event categories above are parsed
and covered by the test suite (synthetic fixtures — the dev box has no Linux
log data, as with the other `linux_*` tools). Not yet done: `klog` ring-buffer
files, `lastlog`-style binary siblings (see `linux_utmp`), per-boot grouping,
and joining SSH events to `linux_utmp` sessions (planned as a cross-tool step).
See the project roadmap.
