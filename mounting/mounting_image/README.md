# mounting_image

**Read-only access to forensic disk images.** Presents `raw` / split-raw /
EWF (`E01`) / VHD / VMDK containers as one seekable byte stream, enumerates
their **MBR / GPT partitions**, and lets you:

- **inspect** the container and partition table (`info`, `partitions`)
- **export** the whole disk or a single partition to a raw file (`convert`,
  `extract`)
- **stream** an arbitrary byte range to stdout (`cat`)
- **serve** the disk or a partition **read-only over NBD** (`serve`), so a
  Linux box can `nbd-client` + `mount -o ro` it with no writes ever reaching
  the evidence

CLI and a **tkinter GUI** (`mounting_image gui`). Zero third-party
dependencies — a `.E01` acquired on Windows is opened and carved on Linux or
macOS.

```
mounting_image info disk.E01
mounting_image partitions disk.E01 --json parts.json
mounting_image convert disk.E01 disk.raw
mounting_image extract disk.vmdk --partition 2 --out part2.raw
mounting_image cat disk.vhd --offset 0x100000 --size 512 | xxd
mounting_image serve disk.E01 --partition 2 --port 10809
```

---

## Install

Requires **Python 3.11+** (`tkinter` for the GUI — ships with python.org
builds; `apt install python3-tk` on Debian).

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/mounting/mounting_image
pip install -e .
```

---

## Container formats

| Format | Support |
|---|---|
| raw / dd | ✅ single file and split sets (`.001/.002…`, `.aa/.ab…`) |
| EWF / EnCase `E01` | ✅ EWF v1 (`EVF`), stored + zlib chunks, single or multi segment; reads case metadata |
| VHD | ✅ fixed and dynamic (`conectix` / `cxsparse`, BAT + block bitmaps) |
| VMDK | ✅ monolithic & split **sparse** (`KDMV`), **flat** extents via the descriptor; stream-optimized (compressed) is detected and rejected with a message |
| VHDX | ⚠️ detected only — convert first (`qemu-img convert -O raw`) or attach in Windows |

The format is sniffed from the header (and the VHD footer); `--format` forces
it.

## Partition tables

MBR (including extended / logical partitions) and GPT (via the protective
MBR), with type-code → label mapping for the common filesystem, LVM, RAID,
EFI and Apple GUIDs. `partitions --json` emits `start_offset` / `start_lba` /
`length` for every partition — feed those offsets to `windows_mft`,
`recovery_metadata`, etc.

---

## Serving over NBD

`serve` runs a minimal read-only NBD server (fixed-newstyle handshake;
`READ` / `FLUSH` / `DISCONNECT`; `WRITE` and `TRIM` return `EPERM`).

```bash
# terminal 1 - export partition 2
mounting_image serve disk.E01 --partition 2 --port 10809 --name evidence

# terminal 2 - Linux, as root
modprobe nbd
nbd-client -N evidence 127.0.0.1 10809 /dev/nbd0 -persist
mount -o ro,noload /dev/nbd0 /mnt/evidence
```

`serve --attach` prints those commands for you; `serve --attach --run` (root,
Linux) executes them and records the session so `mounting_image list` and
`mounting_image unmount --port 10809 --run` can tear it down.

---

## GUI

```bash
mounting_image gui            # then Browse → Open
mounting_image gui disk.E01
```

Container summary, a partition table, and buttons to **export the selected
partition (or whole disk) to raw**, **copy a partition's start offset**, and
**toggle a local NBD export**.

---

## How it works

Every format implements one interface — `size` and `read(offset, length)`
(zero-filled past EOF). A partition is a `SliceImage` over the parent. Sparse
formats (VHD dynamic, VMDK sparse, EWF) resolve each requested range through
their block / grain / chunk tables and synthesise zeros for unallocated
regions. Nothing is ever opened for writing.

---

## Design choices

- **Read-only, always.** Files open `rb`; the NBD export refuses writes.
- **UTC**, ISO-8601 for any timestamps in metadata.
- **Never crash on bad input.** A malformed table raises a clear `error:`; a
  short read zero-fills.
- **Off-host.** Pure Python parsing — no `libewf`, no loop devices needed to
  read.

---

## Status

raw / split / EWF-v1 / VHD / VMDK-sparse / VMDK-flat and MBR / GPT are parsed
and covered by the test suite, which builds a synthetic image in each format
and checks a full byte round-trip (the dev box has no real acquired images —
validation against `libewf` / `qemu-img` output is a to-do). Not yet done:
VHDX, EWF v2 (`Ex01`), compressed/stream-optimized VMDK, AFF4, `.vdi`, and
APFS / LVM container mapping (planned as `mounting_partitions`). See the
[backlog](../../BACKLOG.md).
