# browser_cookies

**Cookies from the browser stores on a disk image.** Reads the Chromium
family (Chrome, Edge, Brave, Opera, Vivaldi), Firefox / Tor Browser
(`cookies.sqlite`) and Safari (`Cookies.binarycookies`, a packed binary
format) and normalises every cookie: host, name, path, expiry, creation
and last-access time, the `Secure` / `HttpOnly` / `SameSite` flags, and
whether it is a session cookie.

![`browser_cookies --gui`](docs/screenshot.png)

```
browser_cookies /mnt/evidence/Users --csv cookies.csv
browser_cookies /cases/img/Users --auth-only --json sessions.json
browser_cookies ./Cookies --host example.com
browser_cookies /mnt/img/Users --notable-only --min-severity high
```

**Read-only and WAL-safe** - the database and any `-wal` / `-shm` side
files are copied to a scratch directory first; the evidence file is never
modified and its timestamps do not change. Pure standard library,
cross-platform.

---

## Values

Cookie **values are metadata only by default**:

* Chromium encrypts values (DPAPI + AES-GCM on Windows, keychain on
  macOS / GNOME) - only the ciphertext length is reported.
* Firefox and Safari store values in the clear - they are read but **not
  printed** unless you pass `--with-values`.

Decryption of the Chromium blobs is out of scope for this tool.

---

## Why it matters

* **Proof of an authenticated session** - a `session/auth-cookie` flag
  (names like `SID`, `PHPSESSID`, `JSESSIONID`, `__Secure-1PSID`,
  `X-APPLE-WEBAUTH-TOKEN`, `*_token`, `oauth*`) means the user *was logged
  in* to that host. With the creation and last-access times you get the
  window of the session.
* **Attacker infrastructure** - a cookie for an **IP-literal host**, an
  `ngrok` / `trycloudflare` **tunnel**, an anonymiser, or a suspect TLD
  is not something a normal browsing session sets.
* **Tampering / spoofing** - a `__Host-` cookie that is not `Secure`,
  path-`/`, and host-only, or a `__Secure-` cookie without `Secure`,
  violates the browser's own prefix rules.
* **Persistence** - a cookie set to expire more than five years out.

Flags are severity-scored; `--auth-only` / `--notable-only` /
`--min-severity` cut straight to the interesting rows.

---

## Output

`--csv` (UTF-8 BOM, formula-injection safe) / `--json` columns:
`host`, `name`, `path`, `browser`, `profile`, `created`, `last_access`,
`expires`, `session`, `secure`, `http_only`, `samesite`, `value_len`,
`notable`, `severity`, `source_db` (+ `value` with `--with-values`).

| filter | |
|---|---|
| `--browser NAME` | one browser |
| `--host SUBSTR` / `--name SUBSTR` | |
| `--auth-only` | only session / authentication cookies |
| `--session-only` | only cookies with no persistent expiry |
| `--secure-only` | |
| `--notable-only` / `--min-severity` | |
| `--grep REGEX` | match host or name |

---

## Chain of custody

Every run writes a `<output>.manifest.json` sidecar (via the shared
`tracelib`) recording the tool version, the exact command line,
`--case-id` / `--examiner` / `--evidence-id`, start and finish time (UTC),
the host, and the **SHA-256 of every input and output file**. CSV rows carry
`evidence_source` / `parser_confidence` / `tz_provenance` columns; JSON is
wrapped as `{"manifest": {...}, "records": [...]}`. `--no-provenance`
disables it; `--max-input-bytes` / `--max-records` / `--wall-seconds` bound a
run against hostile or oversized evidence.

## Limitations (v0.1)

* No value decryption (Chromium ciphertext, keychain-wrapped values).
* `SameSite` for older Chromium schemas that lack the column is reported
  as `unspecified`.
* Safari's `Cookies.binarycookies` checksum / footer is not verified;
  malformed cookies in a page are skipped.
* Deleted rows in the SQLite free-list are not carved yet.
