# analysis_index

**Full-text index and search over a file collection.** Walk a set of paths,
extract text, build an on-disk inverted index, then run boolean / phrase /
proximity / regex queries and get matching files with keyword-in-context
snippets.

```
analysis_index build ./idx /mnt/evidence/Users
analysis_index search ./idx 'invoice AND (paypal OR bitcoin)'
analysis_index search ./idx '"wire transfer" -template ext:pdf'
analysis_index search ./idx 'password NEAR/5 admin'
analysis_search ./idx '/[a-z0-9._%+-]+@evil\.com/'
```

Zero third-party dependencies — the index is plain **SQLite** (no FTS
extension required), portable between machines.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_index
pip install -e .
```

Installs two commands: `analysis_index` (`build` / `search` / `stats` /
`list`) and `analysis_search` (a shortcut straight to `search`).

---

## Building the index

```bash
analysis_index build ./case-idx /mnt/evidence  /mnt/evidence2
analysis_index build ./case-idx /mnt/evidence            # re-run: only new / changed files
analysis_index stats ./case-idx
analysis_index list  ./case-idx --csv indexed.csv
```

| Switch | |
|---|---|
| `--max-size SIZE` | skip files larger than this (default `50m`) |
| `--reindex` | re-index every file, even unchanged ones |
| `--no-recurse` / `--follow-symlinks` | directory-walk options |

**Text extraction** by type:

| Type | How |
|---|---|
| `.txt .log .csv .json .md .py .html …` | decoded directly (UTF-8 / UTF-16 / cp1252 / latin-1) |
| `.html .xml .svg .plist` | tags stripped, entities decoded, `href` / `src` URLs kept |
| `.docx .xlsx .pptx .odt …` | the document XML inside the zip, tags stripped |
| `.eml .mht` | headers + `text/plain` + stripped `text/html` + attachment names |
| anything else | ASCII **and** UTF-16 string carving (like `strings`) |

The tokeniser also emits "glued" runs — `bob@evil.com`, `10.0.0.5`,
`/etc/cron.d/x`, `HKLM\Software\…` — so regex and exact search work on
emails, IPs, paths and identifiers, not just plain words.

---

## Query language

| Form | Meaning |
|---|---|
| `alpha beta` | both terms (implicit AND) |
| `alpha OR beta` | either |
| `-beta` / `NOT beta` | exclude |
| `"exact phrase"` | consecutive terms |
| `alpha NEAR/5 beta` | within 5 tokens of each other |
| `admin*` | prefix (`admin`, `administrator`, `admins`, …) |
| `/regex/` | terms (incl. glued runs) matching the regex |
| `ext:pdf` `kind:email` `path:downloads` `name:invoice.docx` | filters |

Groups combine: `("wire transfer" OR swift) AND -template ext:pdf,docx`.

```bash
analysis_search ./idx '"merger agreement" NEAR/20 confidential'
analysis_search ./idx 'ssh AND (authorized_keys OR "id_rsa") -example'
analysis_search ./idx '/BEGIN (RSA|OPENSSH) PRIVATE KEY/'
analysis_search ./idx 'ransom kind:email --csv hits.csv'
```

Results are ranked by a tf-idf score. `search` exits **0** if there were
matches, **1** if none — usable in a pipeline. `--csv` / `--json` write
`path`, `score`, `matches`, `kind`, `size`, `snippet`.

---

## How it works

- **Inverted index** in three SQLite tables: `docs` (path / size / mtime /
  kind), `postings` (`term, doc_id, tf, positions`) and `vocab`
  (`term, df`). Positions are varint-delta blobs, so phrase and proximity
  queries are exact.
- **Incremental.** A re-`build` skips files whose mtime is unchanged and
  replaces the postings for files that changed.
- **Regex** queries scan the `vocab` table (every distinct term) in Python
  and expand to a term set — fast for a normal corpus, linear in vocabulary.
- **Snippets** are produced on demand: the few matched files are re-read and
  re-tokenised to map token positions back to character offsets.

---

## Design choices

- **Local & offline.** One SQLite file; copy it, back it up, diff it.
- **Read-only on evidence.** Files are opened `rb`.
- **No compiled extensions.** Works on any stock CPython, no FTS5 needed.
- **UTC**, ISO-8601 index timestamps.

---

## Status

Text / markup / OOXML / email / string-carving extraction, the inverted
index, incremental build, and the full query grammar (boolean, phrase,
`NEAR`, prefix, regex, filters) are covered by the test suite. Not yet done:
real PDF text extraction, RTF, legacy `.doc` / `.xls`, language-aware
stemming, stored highlights (snippets currently re-read the file), and
sharding a very large index. See the project roadmap.
