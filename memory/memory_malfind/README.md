# memory_malfind

**Find injected and unbacked executable memory in a Windows RAM dump.**
Pool-tag scanning for `VadS` allocations - which are **private memory by
construction** (no mapped file behind them). A private region that is also
**executable** is the classic signature of code injection: a reflectively
loaded DLL, a hollowed section, or raw shellcode.

![`memory_malfind --gui`](docs/screenshot.png)

```
memory_malfind MEMORY.DMP
memory_malfind mem.lime --min-confidence medium --csv hits.csv
memory_malfind mem.raw --process powershell --json malfind.json
memory_malfind MEMORY.DMP --rwx-only
```

No per-build symbol profile: the VPN pair sits at a stable offset in the
`_MMVAD_SHORT` node, and the protection bits are read from **both** known
positions (Windows 7 vs 8+). Reads raw / LiME / ELF-core / crash-dump
images (shared `loader.py`). Pure standard library, cross-platform.

---

## What it reports

For every private executable region:

| verdict | meaning |
|---|---|
| `pe` | an `MZ` + valid `PE` header at the region base - a manually / reflectively mapped image |
| `shellcode` | executable, non-PE, with code-like prologue bytes at the start (`push ebp`, x64 frame setup, `fc 48 83 e4 f0` stager, `call $+5`, nop sled …) |
| `rwx-data` | a `PAGE_EXECUTE_READWRITE` region of high entropy - a packed / encrypted payload staged for execution |
| `unbacked-exec` | private + executable with the header not paged in, or no other signal |

Each row carries the owning **process** (PID + name), the VA range and
size, the page protection, the pool tag, Shannon entropy over the first
KiB, and a hexdump of the region start.

`confidence` is **high** for an attributed PE or an attributed RWX region
with code at the start, **medium** for a partial match, **low** for a bare
private-exec region with nothing else. JIT engines (`.NET`, Java, browsers,
`MSBuild`) legitimately allocate RWX - treat low / medium rows as leads and
corroborate with `memory_pslist` and the process's module list.

---

## Process attribution & translation

A `_MMVAD` does not point back at its `_EPROCESS`, so attribution is done by
**testing candidate address spaces**: `memory_malfind` pool-scans for
`_EPROCESS` objects, confirms each one's directory-table base with the
self-referential PML4 entry (`PML4[0x1ED]` points back at the DTB), and
assigns a region to the first process whose page tables actually resolve
its start address. The region's first bytes are then read through those
same tables.

Regions that no process claims are still listed (unattributed) and read
through the kernel DTB.

---

## Filters

| option | keeps |
|---|---|
| `--process SUBSTR` / `--pid N` | one process |
| `--verdict KIND` (repeatable) | `pe` / `shellcode` / `rwx-data` / `unbacked-exec` |
| `--rwx-only` | `PAGE_EXECUTE_READWRITE` regions only |
| `--min-confidence` | drop rows below `low` / `medium` / `high` |
| `--all-exec` | also show plain `EXECUTE` / `EXECUTE_READ` regions (noisier) |

Output is a readable report by default, or `--csv` / `--json`
(`pid`, `process`, `start`, `end`, `size`, `protection`, `vad_type`,
`verdict`, `confidence`, `entropy`, `detail`, `pool_tag`, `phys_offset`).
CSV is UTF-8 with a BOM and formula-injection safe.

---

## Limitations (v0.1)

* **Windows only.**
* `VadS` short VADs (private) only - `Vad ` mapped/image VADs are not
  parsed, so **classic process hollowing** (a legitimate image VAD whose
  on-disk header differs from memory) is out of scope for now.
* Profile-independent scanning trades false negatives for false positives.
* The `_MMVAD_SHORT` flag layout is handled for Windows 7 and 8/10/11 x64;
  exotic builds may mis-read the protection field.
* Not yet tested against a real multi-gigabyte dump - synthetic coverage
  only (a hand-built address space with real page tables).
