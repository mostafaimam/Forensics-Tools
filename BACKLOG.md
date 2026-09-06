# Backlog

Roadmap for the suite. Everything is Python 3.11+, standard library only,
cross-platform (analysis runs anywhere; targets are per-OS), `trace-` prefixed,
UTC-only output, CSV (UTF-8 BOM, injection-safe) + JSON.

Priority order is roughly top-to-bottom within each group.

## Done

- **trace-collect** — targeted triage acquisition (Windows / Linux / macOS), live + VSS, hashing, chain-of-custody manifest
- **trace-recycle** — Recycle Bin: `$I` / `$R` / `INFO2` / `INFO`
- **trace-prefetch** — Prefetch `.pf` v17-31 incl. Windows 10/11 `MAM` compression
- **trace-timeline** — super-timeline builder + viewer (console, self-contained HTML, `tkinter` desktop window); ingests every other tool's CSV/JSON plus generic logs

## Next up

- **trace-carve** — data recovery by **magic bytes / signature carving**: header+footer and structural validators for the common types (JPEG, PNG, GIF, PDF, ZIP/OOXML, GZIP, SQLite, PST, EVTX, MFT records, LNK, MP4, PK-archives, ELF/PE, …), scan a raw image / device / unallocated blob, validate and length-bound each hit, write recovered files + a manifest (offset, size, type, hashes, validation status). Cross-platform.
- **trace-recover** — **metadata-based recovery**: walk a live file-system or image and recover *deleted-but-not-overwritten* files from the file-system metadata (NTFS `$MFT` unallocated entries, FAT directory entries, ext4 journal, HFS+/APFS). Complements `trace-carve` (metadata gives names + timestamps; carving finds the bytes).

## Timeline & review tooling

- **trace-view** — richer standalone HTML/JS timeline explorer (saved views, column chooser, multi-tag, notes) beyond the built-in `--html` page.

## Windows artefact parsers

- **trace-mft** — `$MFT` (+ `$UsnJrnl:$J`, `$Boot`, `$Secure:$SDS`) → file-system timeline, resident data, ADS, timestomping detection
- **trace-evtx** — `.evtx` event logs: binary-XML parser, event-ID/provider/time filters, optional field maps
- **trace-registry** — offline hive parser (`regf`) + value/key search, plus curated plugins (Run keys, Services, UserAssist, ShimCache, AmCache, SAM, network history, USB)
- **trace-lnk** — Shell Link (`.lnk`) binary format + `SHELL_ITEM` id lists
- **trace-jumplist** — `AutomaticDestinations` (OLE compound file) + `CustomDestinations`
- **trace-shellbags** — `BagMRU` / `Bags` from `UsrClass.dat` / `NTUSER.DAT`
- **trace-srum** — `SRUDB.dat` (ESE database) resource-usage tables
- **trace-amcache** / **trace-shimcache** — program-presence / execution
- **trace-usn** — standalone `$UsnJrnl:$J` carver
- **trace-esedb** — generic ESE / JET (`.edb`) reader used by SRUM, Windows Search, WebCacheV01
- **trace-wer** — Windows Error Reporting `.wer` reports
- **trace-bits** — `qmgr.db` / `qmgr*.dat` BITS transfer history

## Linux artefact parsers

- **trace-utmp** — `wtmp` / `btmp` / `utmp` / `lastlog` binary login records → session timeline
- **trace-journal** — systemd journal (`.journal`) binary format reader with field filters
- **trace-syslog** — classic `syslog` / `messages` / `auth.log` normaliser (incl. rotated / gz)
- **trace-audit** — `auditd` `audit.log` records → normalised events
- **trace-bashhist** — shell history across users, with `HISTTIMEFORMAT` timestamps and `.python_history` / `.mysql_history` / `.viminfo`
- **trace-cron** — crontabs, `cron.d`, `cron.*`, `at` jobs, systemd timers → scheduled-execution inventory
- **trace-systemd-units** — unit-file inventory + persistence review (`ExecStart`, `WantedBy`, drop-ins)
- **trace-dpkg** / **trace-rpm** — package install/upgrade/remove history from `dpkg.log` / `history.log` / RPM db
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

## Imaging & FTK-equivalent capabilities

Grouped by the AccessData / Exterro *FTK* feature it corresponds to.

### FTK Imager

- **trace-image** — create forensic images: raw / `dd`, split raw, and `EWF` / `E01` (write support), with MD5 + SHA-1/256 during acquisition and a verification pass. **CLI + GUI** (acquisition wizard, progress, hash log).
- **trace-mount** — read-only mount / expose of raw, `E01`, `VHD(X)`, `VMDK` images and partitions (loopback on Linux; user-space file server / WebDAV elsewhere). **CLI + GUI** (pick image → pick partition → mount point / drive letter, mounted-volume list, unmount).
- **trace-fs** — file-system walker for `NTFS` / `FAT` / `exFAT` / `ext2-4` / `HFS+` / `APFS`: list, extract, recover deleted, timeline `MACB`
- **trace-partitions** — MBR / GPT / APFS-container / LVM map
- **trace-ram** — live memory acquisition (Windows via a driver-less API path where possible; Linux `/proc/kcore` + `LiME` format; macOS best-effort)
- **trace-protected** — Windows "protected files" style collection of locked system hives / logs (overlaps `trace-collect --backend vss`)

### FTK core (analysis platform)

- **trace-index** — build a full-text index over a collection / image (tokeniser + on-disk inverted index), then `trace-search` for boolean / phrase / regex / proximity queries
- **trace-kff** — Known File Filter: hash a target set and tag against known-good / known-bad hash sets (NSRL-compatible import), alert on notable hashes
- **trace-carve** — signature-based file carving (headers/footers + structural validators) from unallocated space or a raw image
- **trace-email** — `PST` / `OST` / `MBOX` / `EML` / `MSG` parsing → message + attachment inventory, threading, header analysis
- **trace-registry-report** — FTK "Registry Viewer"-style curated report bundles (built on `trace-registry`)
- **trace-gallery** — extract + thumbnail all pictures/video, EXIF / GPS, perceptual-hash grouping
- **trace-ole** — OLE2 / compound-file + Office / OLE metadata extraction
- **trace-dedupe** — hash-based dedupe + "distinct files" set across a collection
- **trace-encryption** — detect encrypted / password-protected files and containers (BitLocker, Office, PDF, archives, VeraCrypt heuristics); report only — no cracking
- **trace-report** — case report generator: bundle findings, tagged rows, and a `trace-timeline` export into one HTML/JSON package

> Password recovery / decryption cracking (PRTK / DNA equivalents) are
> intentionally **out of scope**. Detection and reporting of encryption is in
> scope; breaking it is not.

## Cross-cutting

- Shared `tracelib` helper package (FILETIME/epoch/HFS-time conversion, UTF-16 helpers, CSV-injection-safe writers, ESE/SQLite readers) once duplication across tools justifies it — each tool stays zero-dependency.
- `trace` umbrella CLI that dispatches to every sub-tool.
- Man pages / `--help` examples parity.
