# memory_image

**Identify, map and convert RAM dumps.** Presents a physical-memory dump as
one addressable space — `read_physical(addr, size)` with zero-fill for gaps —
reports its format, physical range map and OS hints, and converts between
`raw` / `lime` / `padded` layouts or carves out a region.

| Format | Detected by | Notes |
|---|---|---|
| `raw` | fallback | whole file is physical memory from 0 |
| `lime` | `LiME` magic | walks the per-range headers |
| `elf` | `\x7fELF` + `ET_CORE` | `PT_LOAD` segments (`/proc/kcore`, `gcore`, VirtualBox `.elf`) |
| `winkdump` | `PAGE` + `DU64` / `DUMP` | 64/32-bit crash dump — physical runs + `DirectoryTableBase` / `PsActiveProcessHead` from the header |
| `winbmp` | `SDMP` / `FDMP` | bitmap (kernel/full) crash dump — present-page bitmap |

`memory_image.loader.MemoryImage` is the shared loader the other `memory_*`
tools use. Zero third-party dependencies.

```
memory_image info mem.lime
memory_image ranges MEMORY.DMP --json ranges.json
memory_image convert mem.lime mem.raw --format raw
memory_image carve mem.lime --physical 0x1000 --size 4096 --out page.bin
memory_image read mem.raw --physical 0x0 --size 64
```

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/memory/memory_image
pip install -e .
```

---

## Usage

### `info` — what is this dump?

```bash
memory_image info mem.lime
#  format        : lime
#  physical size : 8589934592 (8.0 GiB)
#  mapped        : 8573157376 (8.0 GiB) in 3 run(s)
#    os                      : linux
#    kernel                  : 6.1.0-18-amd64
```

For a Windows crash dump the OS hints come straight from the header
(`directory_table_base`, `ps_active_process_head`, `number_processors`,
`dump_type`); for raw / LiME / ELF, `info` scans for the `Linux version …`
banner and Windows kernel signatures (`--no-scan` to skip).

### `ranges` — the physical map

```bash
memory_image ranges mem.lime --json ranges.json
```

Every `phys_start` / `phys_end` / `size` / `file_offset` — the map the other
`memory_*` tools translate addresses through.

### `convert` — transcode

```bash
memory_image convert MEMORY.DMP mem.lime  --format lime     # for tools that want LiME
memory_image convert mem.lime  mem.raw    --format raw      # compact, ranges concatenated
memory_image convert mem.lime  mem.padded --format padded   # flat physical image (sparse)
```

### `carve` / `read`

```bash
memory_image carve mem.lime --physical 0x1fe00000 --size 0x200000 --out region.bin
memory_image read  mem.lime --physical 0x0 --size 512            # hexdump
memory_image read  mem.lime --physical 0x0 --size 512 --raw | xxd
```

---

## How it works

Each format is reduced to a list of **runs** — `(phys_start, size,
file_offset)`. `read_physical` walks the runs covering the requested range,
seeks to `file_offset + (addr − phys_start)`, and synthesises zeros for any
physical gap (unmapped RAM, MMIO holes) so callers never see a short read.

---

## Design choices

- **Read-only.** The dump is opened `rb`.
- **Never short-read.** Gaps and truncation zero-fill.
- **One loader.** The `memory_*` tools vendor `loader.py` so each stays
  independently installable with zero dependencies.

---

## Status

raw / LiME / ELF-core / Windows full-crash-dump parsing, the range model,
`read_physical` (including span-and-hole cases), all three conversions and
`carve` / `read` are covered by the test suite (synthetic dumps in every
format — the dev box has no real captures). Not yet done: Windows bitmap
dumps beyond basic present-page mapping, `hiberfil.sys` decompression, AVML
container framing, VMware `.vmem` + `.vmsn` pairing, and virtual-address
translation (that needs the page tables — a job for the analysis tools). See
the [backlog](../../BACKLOG.md).
