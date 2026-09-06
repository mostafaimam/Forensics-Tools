# linux_utmp

**Linux login-record parser.** Reads `wtmp` / `btmp` / `utmp` and `lastlog`
into a record timeline and — for `wtmp` — into paired **login / logout
sessions** with durations.

![`linux_utmp --gui`](docs/screenshot.png)

```
linux_utmp /var/log/wtmp --sessions --csv sessions.csv
linux_utmp /var/log/btmp --csv failed_logins.csv
linux_utmp /var/log/wtmp.1.gz /var/log/wtmp --csv all.csv
linux_utmp /var/log/lastlog --csv lastlog.csv
```

Zero third-party dependencies, cross-platform — analyse a Linux image's login
records from Windows or macOS.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/linux/linux_utmp
pip install -e .
```

---

## Usage

The file type is guessed from the name and content; `--as` forces it.
`.gz` (rotated) logs are decompressed automatically. Pass several files at once
(e.g. `wtmp` and its rotations) — records are merged and sorted.

```bash
# every record, newest last
linux_utmp /var/log/wtmp --csv records.csv

# login / logout sessions with durations; "still_open" flags sessions with
# no matching logout (crash, kill -9, or the log rotated mid-session)
linux_utmp /var/log/wtmp --sessions --csv sessions.csv

# brute-force / failed SSH logins
linux_utmp /var/log/btmp --csv failed.csv

# last login per UID
linux_utmp /var/log/lastlog --csv lastlog.csv
```

| Switch | |
|---|---|
| `--sessions` | emit paired sessions instead of raw records (`wtmp`) |
| `--as wtmp\|btmp\|utmp\|lastlog` | force the record type |
| `--user NAME` | keep only this user |
| `--type USER_PROCESS,BOOT_TIME,…` | keep only these record types |
| `--from` / `--to` | inclusive time bounds |
| `--big-endian` | records are big-endian (s390x, ppc64) |
| `--csv` / `--json` | output files |

### Record CSV columns

`index`, `timestamp_utc`, `type` (`USER_PROCESS`, `DEAD_PROCESS`, `BOOT_TIME`,
`LOGIN_PROCESS`, `RUN_LVL`, …), `user`, `line` (tty), `host`, `address`
(IPv4/IPv6 from `ut_addr_v6`), `pid`, `session`, `exit_termination`,
`exit_code`, `source_file`.

### Session CSV columns

`user`, `line`, `host`, `address`, `pid`, `login_utc`, `logout_utc`,
`duration_seconds`, `still_open`, `source_file`.

All timestamps are ISO-8601 **UTC**.

---

## How it works

```
utmp / wtmp / btmp  →  384-byte records:
    int16 ut_type · int32 ut_pid · char[32] ut_line · char[4] ut_id
    char[32] ut_user · char[256] ut_host · exit status · int32 ut_session
    int32 tv_sec/tv_usec · int32[4] ut_addr_v6 · reserved
   │
sessions:  USER_PROCESS opens a session on a tty
           DEAD_PROCESS on the same tty closes the most recent open one
           BOOT_TIME closes every open session (unclean shutdown)
   │
lastlog  →  flat array indexed by UID, 292-byte entries
            (int32 time · char[32] line · char[256] host)
```

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix.
- **Never crash.** A truncated trailing record is ignored; an unparseable
  record is skipped.
- **Little-endian by default** (x86-64, arm64); `--big-endian` for the rare
  exceptions.
- **Off-host.** Pure struct parsing — no `utmp` library, no `/var/run`.

---

## Status

The glibc 64-bit `struct utmp` (384 bytes) and `lastlog` (292 bytes) layouts
are implemented and covered by tests using synthetic records. Validation
against real distro `wtmp` / `btmp` from a range of glibc versions (and musl,
whose `utmp` is a stub) is welcome. 32-bit `struct utmp` and the older
`utmpx` variants are on the backlog.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

14 tests: record parsing, IPv4 decode, session pairing (incl. `BOOT_TIME`
closing open sessions and never-logged-out sessions), `btmp`, `lastlog`,
gzip input, filters, and trailing-garbage tolerance.

## License

MIT — see [LICENSE](LICENSE).
