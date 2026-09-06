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
| `memory/` | Memory forensics |
| `analysis/` | Timeline & analysis |
| `utilities/` | Utilities & viewers |

---

## Done

- **acquisition_collect** — targeted triage acquisition (Windows / Linux / macOS), live + VSS, hashing, chain-of-custody manifest
- **acquisition_ram** — live memory acquisition: Linux physical RAM via `/proc/kcore` + `/proc/iomem` → LiME / raw / padded, streaming MD5+SHA-1+SHA-256; Windows / macOS collect the memory-bearing files (page file, `hiberfil.sys` / `sleepimage`, crash dumps), `--source` for a mounted image; acquisition log + JSON manifest
- **recovery_carve** — file recovery by magic-byte signature carving with structural validators
- **recovery_metadata** — NTFS `$MFT` metadata recovery: list allocated + deleted entries, extract content (incl. deleted), `cat` by entry number
- **windows_registry** — offline `regf` hive parser: dump / key / search / deleted-key recovery, ~50 built-in RegRipper-style plugins (auto-selected by hive kind) + `--plugin-dir` external-plugin loader, `tkinter` browser
- **windows_reglog** — transaction-log (`.LOG1` / `.LOG2`) replay: `HvLE` entries, Marvin32 verification, dirty-hive recovery
- **windows_evtx** — event logs (`.evtx`): from-scratch binary + BinXml parser → standardised CSV / JSON / JSONL / XML, event-ID / provider / level / time filters
- **windows_mft** — NTFS `$MFT` + `$UsnJrnl:$J`: timeline, ADS, `$SI`/`$FN` timestomp detection, bodyfile; `tkinter` `$MFT` browser
- **windows_recycle** — Recycle Bin: `$I` / `$R` / `INFO2` / `INFO`
- **windows_prefetch** — Prefetch `.pf` v17-31 incl. Windows 10/11 `MAM` compression
- **analysis_timeline** — super-timeline builder + viewer (console, self-contained HTML, `tkinter` window)
- **linux_utmp** — `wtmp` / `btmp` / `utmp` / `lastlog` login records → timeline + paired login/logout sessions
- **windows_jumplist** — `automaticDestinations-ms` jump lists: OLE2 reader + `DestList` MRU + embedded `.lnk` per target; AppID resolution
- **windows_lnk** — Shell Link (`.lnk`): target metadata + MAC times, TrackerDataBlock (machine ID + MAC), `BEEF0004` shell items ($MFT refs); `tkinter` viewer
- **windows_amcache** — `Amcache.hve` parser: executables (SHA-1), installed programs, drivers; modern + legacy layouts
- **windows_shimcache** — AppCompatCache / ShimCache parser (program presence + Win7/8 execution), `SYSTEM` hive or live registry
- **macos_plist** — binary + XML property lists → CSV / JSON; `NSKeyedArchiver` unwrapping; Apple timestamp conversion
- **linux_cron** — scheduled-execution inventory: system / user crontabs, `cron.d`, `cron.{hourly,daily,weekly,monthly}`, anacrontab, `at` jobs, systemd timers → one normalised row per job, plain-language schedule, suspicious-entry flags
- **linux_syslog** — classic text-log normaliser: `syslog` / `messages` / `auth.log` / `secure` (+ rotated / `.gz`), BSD + RFC 5424 formats → record timeline or structured security events (SSH / sudo / su / PAM / session / cron / account)
- **linux_bashhist** — shell / REPL history across all users (bash / zsh / fish / sh + python / mysql / psql / sqlite / node / redis), per-shell timestamp parsing, merged timeline, tampering markers, attacker-command heuristics
- **mounting_image** (+GUI) — read-only access to raw / split / EWF (`E01`) / VHD / VMDK images: container + MBR/GPT partition inspection, export whole-disk or per-partition raw, byte-range stream, **built-in read-only NBD server + client** (`nbd://` URLs as a source, `--pull` any OS, Linux `/dev/nbdN` kernel attach, no `nbd-client`), **`mount` as a real read-only drive** (Windows drive letter via fixed-VHD + `Mount-DiskImage`; macOS `hdiutil`; Linux `losetup`+`mount`), `tkinter` browser with a drive-letter picker
- **acquisition_image** (+GUI) — create + verify forensic images: raw / split / EWF (`E01`) **write**, streaming MD5+SHA-1+SHA-256, bad-sector zero-fill + logging, embedded EWF case metadata & digest, acquisition log + JSON manifest + HTML report; disk enumeration (Linux/macOS/Windows); `tkinter` wizard
- **analysis_kff** — Known File Filter: import NSRL RDS (text + SQLite), Project VIC / CAID JSON, HashKeeper / generic CSV, plain hash lists into a local SQLite index; classify files or a hash list as known-good / known-bad / notable / unknown (`scan`, `lookup`, `--alerts-only`, deterministic exit code)
- **analysis_index** / **analysis_search** — full-text index (SQLite inverted index, no FTS extension) over a collection: text / markup / OOXML / email / string-carving extraction, glued tokens for emails·IPs·paths; boolean / phrase / `NEAR/n` / prefix / `/regex/` / `ext:`·`path:`·`kind:` filter queries with KWIC snippets; incremental re-build

## Next up

1. **windows_mft** — `$Boot`, `$SDS` security descriptors, `$ATTRIBUTE_LIST` (heavily fragmented files), `$LogFile`; `--offset` partition auto-detection; short-name / hard-link columns.
2. **recovery_metadata** — FAT / exFAT, ext2-4 (+ journal), HFS+, APFS; `--offset` partition auto-detection; live-volume input (`\\.\C:`).
3. **windows_evtx** — event-ID → friendly-description **maps** (TOML), locale message resolution, recovered records from chunk slack, CRC verification.
4. **windows_reglog** — old-format (`DIRT`) Windows 7 logs; auto-invoke from `windows_registry`.
5. **analysis_encryption** — detect encrypted / password-protected files and containers (report only), per the user's FTK-parity ask.

## Acquisition — `acquisition/`

- **acquisition_image** (+GUI) — done (above). Remaining: EWF v2 (`Ex01`), AFF4, resumable acquisition, remote (SSH / iSCSI) sources, entropy-aware compression.
- **acquisition_ram** — done (above). Remaining: LiME `--compress`, AVML-compatible output, non-x86-64 `PAGE_OFFSET` layouts, an optional Windows kernel-driver path, `hiberfil.sys` / `sleepimage` → raw (overlaps `memory_image`).

## Imaging & mounting — `mounting/`

- **mounting_image** (+GUI) — done (above). Remaining: VHDX, EWF v2 (`Ex01`), compressed/stream-optimized VMDK, AFF4, `.vdi`; a **FUSE / WebDAV** path so a partition's filesystem shows as a browsable folder with **no full-image copy** on Windows/macOS (the current `mount` materialises a VHD/raw first).
- **mounting_vsc** (+GUI) — enumerate and mount all Volume Shadow Copies on a volume to a chosen mount point / drive letter.
- **mounting_partitions** — MBR / GPT / APFS-container / LVM map (no mount, just the layout).

## Recovery — `recovery/`

- (see **Next up** for `recovery_metadata` file-system coverage)
- **recovery_fs** — generic read-only file-system walker (NTFS / FAT / exFAT / ext / HFS+ / APFS): list, extract, timeline `MACB`, feed `analysis_timeline`. Shares the `recovery_metadata` engine.

## Windows artefact parsers — `windows/`

- **windows_mft** / **windows_evtx** / **windows_registry** — see **Next up** for the remaining work (`sk` security descriptors, class-name data, multi-hive load, RegBack diffing).
- **windows_reglog** — see **Next up** (old-format `DIRT` logs; auto-invoke from `windows_registry`).
- **windows_recentfilecache** — `RecentFileCache.bcf` parser.
- **windows_lnk** — see **Next up** (fuller shell-item type coverage, `PropertyStoreDataBlock`).
- **windows_jumplist** — `customDestinations-ms` (non-OLE), DestList v1 (Win7) validation, `tkinter` viewer.
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
- **linux_syslog** — done (above). Remaining: `klog` ring-buffer files, per-boot grouping, join SSH events to `linux_utmp` sessions.
- **linux_audit** — `auditd` `audit.log` records → normalised events
- **linux_bashhist** — done (above). Remaining: `.viminfo` command history, `atuin` / `mcfly` SQLite history DBs, correlate with `linux_utmp` sessions.
- **linux_cron** — done (above). Remaining: resolve systemd `OnCalendar` to concrete next-run times; `fcron` / generator output; per-file owner from image inode metadata.
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

## Memory forensics — `memory/`

Analysis of RAM images captured by `acquisition_ram` (or any raw / LiME / crash
dump). Pure-Python, zero-dependency, read-only; profile/symbol data ships as
plain data files rather than a downloaded symbol server.

- **memory_image** — done. Format ID (raw / LiME / ELF core / Windows crash dump + bitmap dump), physical run map, `read_physical` with zero-fill, OS hints (DTB / PsActiveProcessHead from a crash-dump header, `Linux version` banner scan), convert raw ↔ lime ↔ padded, carve / read a physical region. Shared `loader.py`. Remaining: `hiberfil.sys` decompression, AVML framing, `.vmem`+`.vmsn`, virtual-address translation via page tables.
- **memory_pslist** — v0.1 done: **pool-tag `psscan`** (profile-independent `_EPROCESS` heuristic — name / CreateTime / ExitTime / PID; finds hidden + exited; confidence + dedup). Remaining: a profile-driven `PsActiveProcessLinks` walk (needs vaddr translation from the crash-dump DTB), cross-view diff for DKOM, command line / SID / session / DLL list, Linux `task_struct` scanning.
- **memory_dlllist** — loaded modules / mapped images per process (PEB + VAD cross-check), load path, load reason, unlinked-module detection; dump a module or the main image.
- **memory_handles** — open handles per process (files, keys, events, sections, tokens, threads) and kernel object table.
- **memory_netscan** — network connections and listening sockets (TCP/UDP, v4/v6), owning PID, state, timestamps; pool-scan for closed connections.
- **memory_malfind** — injected / unbacked executable memory: private RWX VADs, PE headers with no backing file, hollowed images, shellcode heuristics; dump the regions.
- **memory_cmdline** / **memory_consoles** — process command lines and reconstructed console/`conhost` screen + history buffers (attacker keystrokes and output).
- **memory_registry** — locate hives in memory (`hivelist`), export them to disk, and run `windows_registry` plugins directly against the in-memory hive; recover keys/values only present in RAM.
- **memory_hashdump** / **memory_lsasecrets** — SAM/SYSTEM in memory → local NT hashes; LSA secrets and cached-domain-credential material. **Reporting/extraction for IR; no cracking.**
- **memory_filescan** / **memory_dumpfiles** — `_FILE_OBJECT` scan and reconstruct file contents from the cache manager (data + image sections).
- **memory_svcscan** — services from memory (`services.exe` records), state, binary path, DLL.
- **memory_timers** / **memory_callbacks** / **memory_ssdt** — kernel persistence & hooking surface: timers, notification callbacks, SSDT / IDT / IRP-hook inspection.
- **memory_strings** — done. ASCII + UTF-16LE runs tagged with the physical address; built-in IOC pattern library (url/email/ip/registry/powershell/cmdline/keys/wallets/cards…); `--classified` / `--category` / `--grep` / `--physical-from/-to`. Remaining: inflate compressed regions before scanning, per-process attribution (needs the structural tools).
- **memory_linux** — Linux dump support for the above where it applies (task list, `lsmod`, `netstat`, `bash` history, mount table, `tty` buffers, injected VMAs) driven by a bundled per-kernel structure-layout file, plus a helper to generate that file from a live host or `vmlinux`/`System.map`.
- **memory_macos** — macOS dump support (proc list, `kextstat`, network, trustcache) — best-effort, version-gated.
- **memory_yara** — scan process / kernel memory with YARA-style rules (bundled minimal matcher, no `yara-python`), report owner + address.

## Timeline & analysis — `analysis/`

- **analysis_view** (GUI-first) — standalone viewer for CSV and Excel (`.xlsx`): per-column filters (distinct-value pick lists), full-text search, multi-column sort, column show/hide/reorder/pin, conditional row-colouring rules, a details pane, a notes/skip column, coloured tags + tag groups, group-by-column, export the current view. Generalises `analysis_timeline`'s viewer to *any* tabular file and brings it to full timeline-review feature parity — while running on Linux/macOS and building a single shareable HTML file. `analysis_timeline --html` becomes a thin wrapper over it.
- **analysis_index** / **analysis_search** — done (above). Remaining: real PDF / RTF / legacy `.doc`·`.xls` text extraction, stemming, stored highlights, index sharding.
- **analysis_kff** — done (above). Remaining: incremental RDS delta imports, NSRL unique/full handling, shared classification cache for `analysis_dedupe` / `analysis_report`.
- **analysis_email** — `PST` / `OST` / `MBOX` / `EML` / `MSG` → message + attachment inventory, threading, header analysis.
- **analysis_gallery** — extract + thumbnail pictures / video, EXIF / GPS, perceptual-hash grouping.
- **analysis_dedupe** — done. Size-prefiltered content grouping, reclaimable bytes, distinct-file list, `--against` baseline diff (new vs seen). Remaining: fuzzy/similarity dedupe, shared hash cache.
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
