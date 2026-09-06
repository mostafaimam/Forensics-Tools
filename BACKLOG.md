# Backlog

Roadmap for the suite. Everything is Python 3.11+, standard library only,
cross-platform (analysis runs anywhere; collection targets are per-OS),
`trace-` prefixed, UTC-only output, CSV (UTF-8 BOM, injection-safe) + JSON.
GUI-bearing tools ship the GUI as a stdlib `tkinter` window **and** a
self-contained HTML view; the CLI always works headless.

Priority is roughly top-to-bottom within each group.

## Done

- **trace-collect** — targeted triage acquisition (Windows / Linux / macOS), live + VSS, hashing, chain-of-custody manifest
- **trace-recycle** — Recycle Bin: `$I` / `$R` / `INFO2` / `INFO`
- **trace-prefetch** — Prefetch `.pf` v17-31 incl. Windows 10/11 `MAM` compression
- **trace-timeline** — super-timeline builder + viewer (console, self-contained HTML, `tkinter` window); ingests every other tool's CSV/JSON plus generic logs
- **trace-recover** — file recovery by magic-byte signature carving with structural validators (carving phase; see phase 2 below)

## Next up

1. **trace-recover phase 2 — metadata recovery.** Walk a live file system or an
   image and recover files (incl. *deleted-but-not-overwritten*) from
   file-system metadata, with original names / paths / `MACB` times:
   NTFS `$MFT`, FAT / exFAT directory entries, ext2-4 (+ journal), HFS+, APFS.
   Includes an "extract one file by MFT-entry / inode number" mode and an
   "extract everything (incl. deleted) to an output tree" mode. This is the
   capability `trace-recover` does **not** have today.
2. **trace-mft** — `$MFT` (+ `$J`, `$Boot`, `$SDS`, `$I30`, `$LogFile`) → file-system timeline, resident data, ADS, `$FN` vs `$SI` timestomping flags. Ships a **`trace-mft` GUI** graphical `$MFT` browser (tree + record detail + hex).
3. **trace-evtx** — `.evtx` event logs: binary-XML parser, standardised CSV / XML / JSON output, event-ID / provider / time filters, and user-supplied field **maps** (YAML-free, TOML) for friendly columns. Locked-file aware via `trace-collect`.

## Windows artefact parsers

Each is a command-line tool; the ones marked **+GUI** also get a `tkinter`
viewer.

- **trace-registry** (+GUI) — offline hive parser (`regf`): key/value tree, search, multi-hive load, deleted-key recovery, transaction-log replay, and curated plugins (Run keys, Services, UserAssist, ShimCache, AmCache, SAM users, network history, USB, typed paths, RecentDocs, …). Batch mode with plugin bundles for scripted reporting.
- **trace-reglog** — replay registry transaction logs (`.LOG1` / `.LOG2`) into a hive so downstream tools see a clean (non-dirty) hive.
- **trace-amcache** — `Amcache.hve` (program presence / installation / driver / device data).
- **trace-shimcache** — `AppCompatCache` / ShimCache (SYSTEM hive) execution & presence order.
- **trace-recentfilecache** — `RecentFileCache.bcf` parser.
- **trace-lnk** (+GUI) — Shell Link (`.lnk`) binary format, `LinkTargetIDList` shell items, extra data blocks, MAC times, machine ID / volume serial.
- **trace-jumplist** (+GUI) — `AutomaticDestinations` (OLE compound file, embedded LNK streams + `DestList`) and `CustomDestinations`.
- **trace-shellbags** (+GUI) — `BagMRU` / `Bags` from `UsrClass.dat` / `NTUSER.DAT`: folder-access tree with first/last interacted times.
- **trace-srum** — `SRUDB.dat` (ESE) network / process / energy / push-notification tables, optionally joined with the SOFTWARE hive for interface names.
- **trace-sum** — Microsoft User Access Logs (`C:\Windows\System32\LogFiles\SUM\*.mdb`) client-access history.
- **trace-w10timeline** — Windows 10/11 Timeline (`ActivitiesCache.db`, SQLite) app / file activity.
- **trace-sqlmap** — locate SQLite databases anywhere in a target and process them with named **maps** (per-artefact SQL + column definitions) → CSV / JSON.
- **trace-esedb** — generic ESE / JET (`.edb`) reader used by SRUM, Windows Search (`Windows.edb`), `WebCacheV01.dat`.
- **trace-usn** — standalone `$UsnJrnl:$J` parser / carver.
- **trace-sdb** (+GUI) — application shim database (`.sdb`) parser (persistence / injection review).
- **trace-wer** — Windows Error Reporting `.wer` reports.
- **trace-bits** — `qmgr.db` / `qmgr*.dat` BITS transfer history.
- **trace-strings** — string extraction (ASCII + UTF-16LE/BE), built-in regex library (URLs, emails, IPs, GUIDs, registry paths, base64, credit-card, …), offset output, locked-file aware. The general-purpose "find the strings" utility.
- **trace-hash** — hash any set of files / a directory tree / an image's files with one or more algorithms → manifest; feeds `trace-kff`.

## Viewers (GUI-first)

- **trace-view** — standalone viewer for CSV and Excel (`.xlsx`) files: per-column Excel-style filters (distinct-value pick lists), full-text search, multi-column sort, column show/hide/reorder/pin, conditional row colouring rules, a details pane for the selected row, a notes/skip column, coloured tags + tag groups, group-by-column, and export of the current view. This is `trace-timeline`'s HTML/`tkinter` viewer generalised to *any* tabular file and brought to feature parity with a dedicated timeline-review GUI — plus the things such GUIs lack: it runs on Linux/macOS, opens the merged output directly, and the HTML build is a single shareable file. `trace-timeline --html` becomes a thin wrapper over it.
- **trace-ezview** — standalone, zero-dependency viewer for `.txt` / `.log` / `.csv` / `.rtf` / `.htm(l)` / `.mht` and, best-effort, `.doc(x)` / `.xls(x)` / `.pdf` text; anything else opens in a built-in hex view with a data-interpreter panel (int/float/FILETIME/DOS-date/GUID at the cursor).
- **trace-hex** — the hex viewer / data interpreter as its own tool and a library other GUIs embed.

## Linux artefact parsers

- **trace-utmp** — `wtmp` / `btmp` / `utmp` / `lastlog` binary login records → session timeline
- **trace-journal** — systemd journal (`.journal`) binary format reader with field filters
- **trace-syslog** — classic `syslog` / `messages` / `auth.log` normaliser (incl. rotated / `.gz`)
- **trace-audit** — `auditd` `audit.log` records → normalised events
- **trace-bashhist** — shell history across users, `HISTTIMEFORMAT` timestamps, `.python_history` / `.mysql_history` / `.viminfo`
- **trace-cron** — crontabs, `cron.d`, `cron.*`, `at` jobs, systemd timers → scheduled-execution inventory
- **trace-systemd-units** — unit-file inventory + persistence review (`ExecStart`, `WantedBy`, drop-ins)
- **trace-dpkg** / **trace-rpm** — package install / upgrade / remove history
- **trace-sshkeys** — `authorized_keys`, `known_hosts`, host keys, `sshd_config` review

## macOS artefact parsers

- **trace-plist** — binary + XML property-list reader → JSON (shared building block)
- **trace-unifiedlog** — `.tracev3` unified-log parser with `uuidtext` / `dsc` string resolution (large effort)
- **trace-fsevents** — `/.fseventsd` gzip records → file-system change timeline
- **trace-knowledgec** — `knowledgeC.db` / CoreDuet (SQLite) app usage, device state
- **trace-quarantine** — `com.apple.LaunchServices.QuarantineEventsV2` (SQLite) downloads
- **trace-spotlight** — `.spotlight-V100` `store.db` metadata
- **trace-launchd** — `LaunchAgents` / `LaunchDaemons` persistence review
- **trace-installhistory** — `InstallHistory.plist` + `/var/db/receipts`
- **trace-tcc** — `TCC.db` privacy permissions
- **trace-dslocal** — `/var/db/dslocal` local account records

## Imaging & acquisition (CLI + GUI)

- **trace-image** (+GUI) — create forensic images: raw / `dd`, split raw, `EWF` / `E01` (write), with MD5 + SHA-1/256 during acquisition and a verification pass; acquisition wizard, progress, hash log.
- **trace-mount** (+GUI) — read-only mount / expose of raw, `E01`, `VHD(X)`, `VMDK`, and partitions (loopback on Linux; user-space file server / WebDAV / drive letter elsewhere); pick image → pick partition → mount, with a mounted-volume list and unmount.
- **trace-vscmount** (+GUI) — enumerate and mount all Volume Shadow Copies on a volume to a chosen mount point / drive letter.
- **trace-partitions** — MBR / GPT / APFS-container / LVM map.
- **trace-ram** — live memory acquisition (Linux `/proc/kcore` + LiME format; Windows / macOS best-effort).

## Analysis platform capabilities

- **trace-index** / **trace-search** — build a full-text index over a collection / image (tokeniser + on-disk inverted index), then boolean / phrase / regex / proximity queries.
- **trace-kff** — Known File Filter: hash a target set and tag against known-good / known-bad hash sets (NSRL-compatible import), alert on notable hashes.
- **trace-email** — `PST` / `OST` / `MBOX` / `EML` / `MSG` → message + attachment inventory, threading, header analysis.
- **trace-gallery** — extract + thumbnail pictures / video, EXIF / GPS, perceptual-hash grouping.
- **trace-ole** — OLE2 / compound-file + Office / OLE metadata extraction.
- **trace-dedupe** — hash-based dedupe + "distinct files" set across a collection.
- **trace-encryption** — detect encrypted / password-protected files and containers (BitLocker, Office, PDF, archives, VeraCrypt heuristics); **report only, no cracking**.
- **trace-report** — case report generator: bundle findings, tagged rows and a `trace-timeline` export into one HTML / JSON package.

> Password recovery / decryption cracking is intentionally **out of scope**.
> Detecting and reporting encryption is in scope; breaking it is not.

## Cross-cutting

- Shared `tracelib` helper package (FILETIME / epoch / HFS / Cocoa time conversion, UTF-16 helpers, CSV-injection-safe writers, ESE / SQLite / OLE readers, the hex/data-interpreter widget) once duplication justifies it — each tool stays zero-dependency.
- `trace` umbrella CLI dispatching to every sub-tool.
- A one-shot downloader / updater script for the whole suite.
- `--help` examples and man-page parity across tools.
