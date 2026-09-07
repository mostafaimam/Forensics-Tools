# memory_netscan

**Recover network connections and listening sockets from a Windows RAM
dump.** Pool-tag scanning for `tcpip.sys` allocations - `TcpE` (TCP
endpoints), `TcpL` (TCP listeners), `UdpA` (UDP endpoints) - so it finds
**connections that are hidden or already closed** and that a live `netstat`
would miss. Each candidate is parsed **by content** (a plausible
`CreateTime`, big-endian ports, a TCP-state enum, kernel pointers that
resolve), so **no per-build symbol profile is needed**.

![`memory_netscan --gui`](docs/screenshot.png)

```
memory_netscan MEMORY.DMP
memory_netscan mem.lime --listeners --csv sockets.csv
memory_netscan mem.raw --proto tcp --established
memory_netscan MEMORY.DMP --process chrome --json net.json
memory_netscan mem.lime --port 4444 --port 443
```

Reads raw / LiME / ELF-core / Windows crash-dump images (shared
`loader.py`). Pure standard library, zero third-party dependencies,
cross-platform.

---

## Why it matters

* **Hidden and dead connections** - a rootkit that unlinks its socket, or a
  beacon that closed minutes ago, is gone from `netstat` but its endpoint
  object is still in the pool. Pool-tag scanning walks physical memory, not
  the live tables.
* **Attribution** - each endpoint carries an `Owner` pointer to its
  `_EPROCESS`. When the address space can be resolved (below) the row gets a
  PID and image name, so "something on this host talked to 4444/tcp" becomes
  "`rundll32.exe` (pid 5140) opened it at 03:14".
* **Timeline** - the inline `CreateTime` FILETIME dates the connection to the
  second, feeding `analysis_timeline`.

---

## Address-space translation

Owning process and local / remote addresses live **behind pointers**, so
resolving them needs virtual-to-physical translation - the kernel
directory-table base (CR3).

`memory_netscan` finds it with no profile:

1. a **crash-dump header** stores the DTB directly - used when present;
2. otherwise it scans for a `System`-like `_EPROCESS`, reads the candidate
   `DirectoryTableBase`, and **confirms it with the self-referential PML4
   entry** - Windows maps the top-level page table into itself at index
   `0x1ED`, so a correct DTB's `PML4[0x1ED]` points back at the DTB.

With the DTB it walks the four x64 paging levels (handling 1 GiB / 2 MiB
large pages) and follows the endpoint's `InetAF`, address-info, and `Owner`
pointers. `--no-translation` skips this: faster, but rows then carry only
what was inline (ports, state, timestamp) at lower confidence.

---

## Output

Columns: `proto`, `role`, `state`, `local_addr`, `local_port`,
`remote_addr`, `remote_port`, `pid`, `process`, `create_time`,
`confidence`, `pool_tag`, `phys_offset`. CSV is UTF-8 with a BOM and is
formula-injection safe.

`confidence` is **high** when a process, a port and a timestamp were all
recovered, **medium** with a partial set, **low** when only the pool tag
and one field survived. Treat low-confidence rows as leads, not facts.

| filter | keeps |
|---|---|
| `--proto tcp` / `udp` | one protocol |
| `--listeners` | listening sockets only |
| `--established` | `ESTABLISHED` TCP endpoints only |
| `--process SUBSTR` | rows whose owning process matches |
| `--port N` (repeatable) | rows using this local or remote port |
| `--min-confidence` | drop rows below `low` / `medium` / `high` |

---

## Limitations (v0.1)

* **Windows only.** Linux socket recovery from a dump is a separate tool.
* Remote addresses and IPv6 resolution depend on chasing structures whose
  layout is build-specific; they are best-effort and may be blank.
* Profile-independent scanning trades false negatives for false positives -
  cross-check surprising rows against `memory_pslist` and the timeline.
* XP / 2003-era `TCPT` / `AddrObj` objects are not parsed.
