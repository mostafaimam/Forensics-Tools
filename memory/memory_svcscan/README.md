# memory_svcscan

**Recover the Windows service database from a RAM dump.** The Service
Control Manager keeps every service as a `_SERVICE_RECORD` in
`services.exe`'s heap, each tagged with the ASCII bytes `sErv`. Scanning
physical memory for that tag and resolving the record's pointers through
`services.exe`'s address space rebuilds the service list **without the
registry** - including services that were deleted from
`HKLM\SYSTEM\CurrentControlSet\Services` but are still registered with the
SCM.

![`memory_svcscan --gui`](docs/screenshot.png)

```
memory_svcscan MEMORY.DMP
memory_svcscan mem.lime --running --csv services.csv
memory_svcscan mem.raw --notable-only --json suspicious.json
memory_svcscan MEMORY.DMP --type kernel-driver
```

No per-build symbol profile: the record layout drifts, so name, display
name, type, state, binary / DLL path and controlling PID are recovered
**by content**. Reads raw / LiME / ELF-core / crash-dump images. Pure
standard library, cross-platform.

---

## Why it matters

* **Persistence that beats the registry** - malware commonly creates a
  service with `sc create` / `CreateService` and then deletes the registry
  key (or hides it with a NULL-embedded name). The SCM's in-memory copy
  still has it, so it shows up here when a registry parse comes up empty.
* **Service triage** - the state (`RUNNING` / `STOPPED` / `*_PENDING`),
  type (`win32-own`, `win32-share`, `kernel-driver`, `user-svc`) and the
  full binary command line for every service, in one table.
* **Anomalies flagged** - a service binary under `\Users\`, `\Temp\`,
  `\ProgramData\`, `\Public\`; a **kernel driver** loaded from a
  user-writable path; a LOLBin (`rundll32`, `regsvr32`, `powershell`,
  `mshta`, `msbuild`, …) as the service binary; an unquoted service path
  with a space (privilege-escalation classic); a random-looking or
  GUID-like service name.

---

## Output

| column | |
|---|---|
| `name` / `display_name` | the SCM key name and its friendly name |
| `type` | `win32-own`, `win32-share`, `kernel-driver`, `fs-driver`, `user-svc`, … |
| `state` | `RUNNING`, `STOPPED`, `START_PENDING`, `STOP_PENDING`, `PAUSED`, … |
| `pid` | controlling process (for a running win32 service) |
| `binary_path` | `ImagePath` / `ServiceDll` command line |
| `notable` / `severity` | heuristic flags |
| `confidence` | `high` when name + type + state + path all resolved |

`--running`, `--type SUBSTR`, `--name SUBSTR`, `--notable-only`,
`--min-severity`, `--min-confidence`. CSV is UTF-8 with a BOM and
formula-injection safe.

---

## Limitations (v0.1)

* **Windows only.**
* The `sErv` tag also appears in freed heap blocks, so a stopped service
  can show twice (the newer record wins on dedup) or a stale row can
  survive - cross-check surprising entries against the registry
  (`windows_registry plugin SYSTEM`).
* The field offsets around the tag are heuristic; an exotic build may
  leave `type` / `state` / `pid` as `?` / `0` (the row is still listed at
  lower confidence).
* Group membership, dependencies, the `FailureActions` and the trigger
  list are not parsed yet.
* Not yet tested against a real multi-gigabyte dump - synthetic coverage
  only (a hand-built `services.exe` heap with real `_SERVICE_RECORD`s).
