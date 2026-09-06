# acquisition_ram

**Live memory acquisition.**

| Platform | What it does |
|---|---|
| **Linux** | reads physical RAM through **`/proc/kcore`** (the kernel's own ELF view of memory), guided by **`/proc/iomem`**, and writes a **LiME** / **raw** / **padded** dump — hashing every byte, with an acquisition log + JSON manifest. Needs root. |
| **Windows** | no driver-free full-RAM read, so it **collects the files that contain memory**: `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`, `MEMORY.DMP`, `Minidump\*.dmp`, `CrashDumps\*.dmp`, WER dumps — each copied and hashed, locked files noted. |
| **macOS** | SIP blocks a live RAM read, so it collects `/private/var/vm/sleepimage` + `swapfile*`, `/cores`, and kernel panic logs. |

For the locked files on Windows / macOS, image the disk and re-run with
`--source /mnt/c --os windows` — the files aren't locked on a mounted copy.

Zero third-party dependencies.

```
acquisition_ram info
sudo acquisition_ram capture mem.lime --format lime --case 2026-014
acquisition_ram capture ./ram_files --source /mnt/c --os windows
acquisition_ram capture out.raw --kcore ./kcore --iomem ./iomem   # offline
```

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/acquisition/acquisition_ram
pip install -e .
```

---

## Usage

### `info` — what can be captured here

```bash
acquisition_ram info                       # this host
acquisition_ram info --source /mnt/c --os windows
```

On Linux it reports whether `/proc/kcore` is readable, the `System RAM`
ranges from `/proc/iomem`, the total, and the detected `PAGE_OFFSET`.

### `capture` — acquire

```bash
# Linux, as root
sudo acquisition_ram capture /evidence/2026-014.lime \
    --format lime --case 2026-014 --examiner "A. Analyst"

# Windows / macOS live (collects the memory-bearing files into a directory)
acquisition_ram capture C:\evidence\ram

# against a mounted image (files not locked)
acquisition_ram capture ./ram_files --source /mnt/win --os windows --only hibernation,page file

# replay a copied /proc/kcore off-host
acquisition_ram capture out.padded --kcore ./kcore --iomem ./iomem --format padded
```

| Switch | |
|---|---|
| `--format lime\|raw\|padded` | Linux dump layout (default `lime`) |
| `--source ROOT` `--os` | collect memory-bearing files from a mounted image |
| `--kcore` / `--iomem` | use copied files instead of `/proc/*` |
| `--only CAT,CAT` | file collection: limit to these categories |
| `--hash md5\|sha1\|sha256` | which hashes (default all three) |
| `--case` / `--evidence` / `--examiner` / `--description` / `--notes` | case metadata |

Every run writes `<out>.txt` (log) and `<out>.json` (manifest) — for file
collection, `acquisition_ram.txt` / `.json` inside the output directory.

### Dump formats (Linux)

| Format | Layout | Use |
|---|---|---|
| `lime` | a 32-byte `LiME` header before each `System RAM` range, then its bytes | the analysis default — memory tools read the range map directly |
| `raw` | the `System RAM` ranges concatenated, no gaps (+ a `.ranges.json` map) | smallest; needs the map to translate offsets |
| `padded` | ranges written at their physical offset, holes zero-filled (sparse) | a flat physical image; largest |

---

## How it works

- **`/proc/iomem`** gives the physical `System RAM` ranges (top-level entries
  only — nested children like `Kernel code` are skipped).
- **`/proc/kcore`** is an ELF core. Its `PT_LOAD` segments are parsed; the one
  whose virtual address is in the `PAGE_OFFSET` window and has the largest
  file size is the **direct map** (physmap), which maps physical address 0 to
  `PAGE_OFFSET` contiguously. Physical address *P* is then read from kcore at
  `direct_map.p_offset + P`.
- Reads are chunked; an unreadable region is zero-filled and noted, never
  fatal.
- MD5 + SHA-1 + SHA-256 update as the dump is written.

If `/proc/kcore` is missing or reads empty (kernel lockdown, containers,
hardened kernels), acquisition_ram says so — capture from a **hypervisor
snapshot** or with a loadable module (**LiME**, **AVML**) instead.

---

## Design choices

- **Read-only.** Nothing about the target is modified.
- **UTC**, ISO-8601 in the log and manifest.
- **Never abort on an unreadable page** — zero-fill, warn, continue.
- **Off-host replay.** `--kcore` / `--iomem` and `--source` let you re-run the
  same logic against copied artefacts from any OS.

---

## Status

`/proc/kcore` + `/proc/iomem` parsing, the three dump formats, streaming
hashing, and Windows / macOS file collection (with a `--source` root) are
covered by the test suite — a synthetic ELF `kcore` + `iomem` drives the
Linux path (the dev box is Windows, so the live `/proc/kcore` read is not
exercised in CI). Not yet done: `/proc/kcore` on non-x86-64 `PAGE_OFFSET`
layouts beyond the detection window, direct LiME **compression**
(`--compress`), AVML-compatible output, a Windows kernel-driver option, and
carving `hiberfil.sys` / `sleepimage` into a raw image (that's a job for the
planned `memory_image`). See the [backlog](../../BACKLOG.md).
