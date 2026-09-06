# Backlog

Roadmap for the suite. Everything is Python 3.11+, standard library only,
cross-platform (analysis runs anywhere; collection targets are per-OS),
UTC-only output, CSV (UTF-8 BOM, injection-safe) + JSON.

Tools are named **`category_tool`** and live in that category's directory.
GUI-bearing tools ship the GUI as a stdlib `tkinter` window **and** a
self-contained HTML view; the CLI always works headless.

Priority is roughly top-to-bottom within each group.

| Category directory | Section |
|---|---|
| `acquisition/` | Acquisition |
| `mounting/` | Imaging & mounting |
| `recovery/` | Recovery |
| `windows/` | Windows artefact parsers |
| `linux/` | Linux artefact parsers |
| `macos/` | macOS artefact parsers |
| `analysis/` | Timeline & analysis |
| `utilities/` | Utilities & viewers |

---

## Done

- **acquisition_collect** — targeted triage acquisition (Windows / Linux / macOS), live + VSS, hashing, chain-of-custody manifest
- **recovery_carve** — file recovery by magic-byte signature carving with structural validators
- **recovery_metadata** — NTFS `$MFT` metadata recovery: list allocated + deleted entries, extract content (incl. deleted), `cat` by entry number
- **windows_registry** — offline `regf` hive parser: dump / key / search / deleted-key recovery, 8 built-in plugins, `tkinter` browser
- **windows_reglog** — transaction-log (`.LOG1` / `.LOG2`) replay: `HvLE` entries, Marvin32 verification, dirty-hive recovery
- **windows_evtx** — event logs (`.evtx`): from-scratch binary + BinXml parser → standardised CSV / JSON / JSONL / XML, event-ID / provider / level / time filters
- **windows_mft** — NTFS `$MFT` + `$UsnJrnl:$J`: timeline, ADS, `$SI`/`$FN` timestomp detection, bodyfile; `tkinter` `$MFT` browser
- **windows_recycle** — Recycle Bin: `$I` / `$R` / `INFO2` / `INFO`
- **windows_prefetch** — Prefetch `.pf` v17-31 incl. Windows 10/11 `MAM` compression
- **analysis_timeline** — super-timeline builder + viewer (console, self-contained HTML, `tkinter` window)
- **linux_utmp** — `wtmp` / `btmp` / `utmp` / `lastlog` login records → timeline + paired login/logout sessions
- **windows_shimcache** — AppCompatCache / ShimCache parser (program presence + Win7/8 execution), `SYSTEM` hive or live registry
- **macos_plist** — binary + XML property lists → CSV / JSON; `NSKeyedArchiver` unwrapping; Apple timestamp conversion

## Next up

1. **windows_mft** — `$Boot`, `$SDS` security descriptors, `$ATTRIBUTE_LIST` (heavily fragmented files), `$LogFile`; `--offset` partition auto-detection; short-name / hard-link columns.
2. **recovery_metadata** — FAT / exFAT, ext2-4 (+ journal), HFS+, APFS; `--offset` partition auto-detection; live-volume input (`\\.\C:`).
3. **windows_evtx** — event-ID → friendly-description **maps** (TOML), locale message resolution, recovered records from chunk slack, CRC verification.
4. **windows_reglog** — old-format (`DIRT`) Windows 7 logs; auto-invoke from `windows_registry`.
5. **mounting_image** (+GUI) — read-only mount of raw / `E01` / `VHD(X)` / `VMDK` images and partitions.

## Acquisition — `acquisition/`

- **acquisition_image** (+GUI) — create forensic images: raw / `dd`, split raw, `EWF` / `E01` (write), MD5 + SHA-1/256 during acquisition and a verification pass; acquisition wizard, progress, hash log.
- **acquisition_ram** — live memory acquisition (Linux `/proc/kcore` + LiME format; Windows / macOS best-effort).

## Imaging & mounting — `mounting/`

- **mounting_image** (+GUI) — read-only mount / expose of raw, `E01`, `VHD(X)`, `VMDK`, and partitions (loopback on Linux; user-space file server / WebDAV / drive letter elsewhere); pick image → pick partition → mount, with a mounted-volume list and unmount.
- **mounting_vsc** (+GUI) — enumerate and mount all Volume Shadow Copies on a volume to a chosen mount point / drive letter.
- **mounting_partitions** — MBR / GPT / APFS-container / LVM map (no mount, just the layout).

## Recovery — `recovery/`

- (see **Next up** for `recovery_metadata` file-system coverage)
- **recovery_fs** — generic read-only file-system walker (NTFS / FAT / exFAT / ext / HFS+ / APFS): list, extract, timeline `MACB`, feed `analysis_timeline`. Shares the `recovery_metadata` engine.

## Windows artefact parsers — `windows/`

- **windows_mft** / **windows_evtx** / **windows_registry** — see **Next up** for the remaining work (more plugins, `sk` security descriptors, multi-hive load, RegBack diffing).
- **windows_reglog** — see **Next up** (old-format `DIRT` logs; auto-invoke from `windows_registry`).
- **windows_amcache** — `Amcache.hve` (program presence / installation / driver / device data).
- **windows_recentfilecache** — `RecentFileCache.bcf` parser.
- **windows_lnk** (+GUI) — Shell Link (`.lnk`) binary format, `LinkTargetIDList` shell items, extra-data blocks, MAC times, machine ID / volume serial.
- **windows_jumplist** (+GUI) — `AutomaticDestinations` (OLE compound file, embedded LNK streams + `DestList`) and `CustomDestinations`.
- **windows_shellbags** (+GUI) — `BagMRU` / `Bags` from `UsrClass.dat` / `NTUSER.DAT`: folder-access tree with first/last interacted times.
- **windows_srum** — `SRUDB.dat` (ESE) network / process / energy / push-notification tables, optionally joined with the SOFTWARE hive for interface names.
- **windows_sum** — Microsoft User Access Logs (`C:\Windows\System32\LogFiles\SUM\*.mdb`) client-access history.
- **windows_timeline** — Windows 10/11 Timeline (`ActivitiesCache.db`, SQLite) app / file activity.
- **windows_sqlmap** — locate SQLite databases anywhere in a target and process them with named maps (per-artefact SQL + column definitions) → CSV / JSON.
- **windows_esedb** — generic ESE / JET (`.edb`) reader used by SRUM, Windows Search (`Windows.edb`), `WebCacheV01.dat`.
- **windows_usn** — standalone `$UsnJrnl:$J` parser / carver.
- **windows_sdb** (+GUI) — application shim database (`.sdb`) parser (persistence / injection review).
- **windows_wer** — Windows Error Reporting `.wer` reports.
- **windows_bits** — `qmgr.db` / `qmgr*.dat` BITS transfer history.

## Linux artefact parsers — `linux/`

- **linux_utmp** — 32-bit `struct utmp`, `utmpx`, musl stub handling; join with `linux_syslog` SSH auth lines.
- **linux_journal** — systemd journal (`.journal`) binary format reader with field filters
- **linux_syslog** — classic `syslog` / `messages` / `auth.log` normaliser (incl. rotated / `.gz`)
- **linux_audit** — `auditd` `audit.log` records → normalised events
- **linux_bashhist** — shell history across users, `HISTTIMEFORMAT` timestamps, `.python_history` / `.mysql_history` / `.viminfo`
- **linux_cron** — crontabs, `cron.d`, `cron.*`, `at` jobs, systemd timers → scheduled-execution inventory
- **linux_units** — systemd unit-file inventory + persistence review (`ExecStart`, `WantedBy`, drop-ins)
- **linux_packages** — `dpkg` / `apt` / `rpm` / `dnf` install-upgrade-remove history
- **linux_sshkeys** — `authorized_keys`, `known_hosts`, host keys, `sshd_config` review

## macOS artefact parsers — `macos/`

- **macos_plist** — `NSKeyedArchiver` class coverage beyond the common set; `--key` glob; validation corpus.
- **macos_unifiedlog** — `.tracev3` unified-log parser with `uuidtext` / `dsc` string resolution (large effort)
- **macos_fsevents** — `/.fseventsd` gzip records → file-system change timeline
- **macos_knowledgec** — `knowledgeC.db` / CoreDuet (SQLite) app usage, device state
- **macos_quarantine** — `com.apple.LaunchServices.QuarantineEventsV2` (SQLite) downloads
- **macos_spotlight** — `.spotlight-V100` `store.db` metadata
- **macos_launchd** — `LaunchAgents` / `LaunchDaemons` persistence review
- **macos_installhistory** — `InstallHistory.plist` + `/var/db/receipts`
- **macos_tcc** — `TCC.db` privacy permissions
- **macos_dslocal** — `/var/db/dslocal` local account records

## Timeline & analysis — `analysis/`

- **analysis_view** (GUI-first) — standalone viewer for CSV and Excel (`.xlsx`): per-column filters (distinct-value pick lists), full-text search, multi-column sort, column show/hide/reorder/pin, conditional row-colouring rules, a details pane, a notes/skip column, coloured tags + tag groups, group-by-column, export the current view. Generalises `analysis_timeline`'s viewer to *any* tabular file and brings it to full timeline-review feature parity — while running on Linux/macOS and building a single shareable HTML file. `analysis_timeline --html` becomes a thin wrapper over it.
- **analysis_index** / **analysis_search** — build a full-text index over a collection / image (tokeniser + on-disk inverted index), then boolean / phrase / regex / proximity queries.
- **analysis_kff** — Known File Filter: hash a target set and tag against known-good / known-bad hash sets (NSRL-compatible import), alert on notable hashes.
- **analysis_email** — `PST` / `OST` / `MBOX` / `EML` / `MSG` → message + attachment inventory, threading, header analysis.
- **analysis_gallery** — extract + thumbnail pictures / video, EXIF / GPS, perceptual-hash grouping.
- **analysis_dedupe** — hash-based dedupe + "distinct files" set across a collection.
- **analysis_encryption** — detect encrypted / password-protected files and containers (BitLocker, Office, PDF, archives, VeraCrypt heuristics); **report only, no cracking**.
- **analysis_report** — case report generator: bundle findings, tagged rows and an `analysis_timeline` export into one HTML / JSON package.

## Utilities & viewers — `utilities/`

- **utilities_strings** — string extraction (ASCII + UTF-16 LE/BE), built-in regex library (URLs, emails, IPs, GUIDs, registry paths, base64, credit-card, …), offset output, locked-file aware.
- **utilities_hash** — hash a file set / directory tree / an image's files with one or more algorithms → manifest; feeds `analysis_kff`.
- **utilities_ole** — OLE2 / compound-file + Office / OLE metadata extraction.
- **utilities_hex** — hex viewer / data interpreter (int / float / FILETIME / DOS-date / GUID at the cursor) as its own tool and a library the GUIs embed.
- **utilities_ezview** — standalone, zero-dependency viewer for `.txt` / `.log` / `.csv` / `.rtf` / `.htm(l)` / `.mht` and best-effort `.doc(x)` / `.xls(x)` / `.pdf` text; anything else opens in `utilities_hex`.

> Password recovery / decryption cracking is intentionally **out of scope**.
> Detecting and reporting encryption is in scope; breaking it is not.

## Cross-cutting

- Shared `tracelib` helper package (FILETIME / epoch / HFS / Cocoa time conversion, UTF-16 helpers, CSV-injection-safe writers, ESE / SQLite / OLE readers, the hex/data-interpreter widget) once duplication justifies it — each tool stays zero-dependency.
- A single umbrella CLI dispatching to every sub-tool.
- A one-shot downloader / updater script for the whole suite.
- `--help` examples and man-page parity across tools.
