# browser_history

**Web history, downloads and typed URLs from a disk image or a live
system.** Reads the **Chromium family** (Chrome, Edge, Brave, Opera,
Vivaldi, Chromium), **Firefox / Tor Browser**, and **Safari** history
stores directly with the standard-library `sqlite3` module and normalises
everything to one schema.

![`browser_history --gui`](docs/screenshot.png)

```
browser_history /mnt/evidence/Users --csv history.csv
browser_history /cases/img/Users --browser chrome --typed-only
browser_history ./History --downloads-only --json downloads.json
browser_history /mnt/img/Users --grep 'mega|anonfiles|pastebin' \
    --from 2026-08-01 --to 2026-08-31
```

**Read-only and WAL-safe.** The database and any `-wal` / `-shm` side
files are copied to a scratch directory first, so the write-ahead log is
checkpointed into *our* copy - the evidence file is never modified and its
timestamps do not change. Pure standard library, cross-platform.

---

## What it recovers

| kind | fields |
|---|---|
| **visit** | URL, page title, UTC visit time, visit count, whether the user **typed** it, transition type (`link` / `typed` / `bookmark` / `redirect` / `form-submit` / `keyword` / …), the referring URL |
| **download** | source URL, referrer / tab URL, target path, bytes, browser's own danger classification, MIME type, start / end time |
| **search** | the query behind a search-engine visit (`keyword_search_terms`, Firefox `moz_inputhistory`) |

Every row carries its `browser`, `profile` (the profile path), and
`source_db`, so a multi-user, multi-browser image collapses to one
sortable timeline that drops straight into `analysis_timeline`.

---

## Why it matters

Browser history answers *what did they look at, download, and search for*:

* **Intent** - a **typed** URL or a search term is a deliberate act
  (`how to disable defender`, `reverse shell`, a competitor's name the
  week before someone quit).
* **Staging & exfil** - visits or downloads involving paste sites
  (`pastebin`, `rentry`), anonymous file hosts (`anonfiles`, `mega`,
  `gofile`, `transfer.sh`), tunnels (`ngrok`, `trycloudflare`), or
  anonymisers.
* **Delivery** - an `.exe` / `.ps1` / `.hta` / `.iso` download, an
  IP-literal host, a punycode look-alike domain, `file://` access to a
  local secret, or a base64 blob smuggled in a URL path.

Suspicious URLs are flagged and severity-scored; `--notable-only` /
`--min-severity` cut a 50 000-row history down to the handful worth
reading.

---

## Output

`--csv` (UTF-8 BOM, formula-injection safe) / `--json` columns:
`time`, `browser`, `profile`, `kind`, `url`, `title`, `from_url`,
`transition`, `typed`, `visit_count`, `detail`, `notable`, `severity`,
`source_db`.

| filter | |
|---|---|
| `--browser NAME` | `chrome` / `edge` / `firefox` / `safari` / … |
| `--profile SUBSTR` | one profile |
| `--kind visit\|download\|search` (repeatable) | |
| `--typed-only` / `--downloads-only` | |
| `--notable-only` / `--min-severity` | |
| `--grep REGEX` | match URL or title |
| `--from` / `--to` | date window (a bare `--to` date is inclusive of that whole day) |

Point it at a mounted image's `Users` / `home` directory, a single
profile folder, or one `History` / `places.sqlite` file.

---

## Limitations (v0.1)

* **Cookies, cache content, autofill, saved logins and session/tab state**
  are separate tools (`browser_cookies`, `browser_cache`, …).
* Firefox download recovery uses the modern `moz_annos` annotations and
  the legacy `downloads.sqlite`; a profile mid-migration may show fewer
  downloads than it had.
* Deleted rows in the SQLite free-list / WAL frames are not carved yet -
  a `--carve` mode is planned.
* Value decryption (encrypted cookie values, saved passwords) is out of
  scope; only metadata is read.
