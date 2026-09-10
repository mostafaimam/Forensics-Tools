# mounting_image

**Read-only access to forensic disk images.** Presents `raw` / split-raw /
EWF (`E01`) / VHD / VMDK containers as one seekable byte stream, enumerates
their **MBR / GPT partitions**, and lets you:

![`mounting_image gui` — container + partitions, export, NBD, mount](docs/screenshot.png)

- **inspect** the container and partition table (`info`, `partitions`)
- **export** the whole disk or a single partition to a raw file (`convert`,
  `extract`)
- **stream** an arbitrary byte range to stdout (`cat`)
- **mount as a real read-only drive** (`mount`) — a **Windows drive letter**
  (via a fixed VHD + `Mount-DiskImage`), a macOS volume (`hdiutil`), or a
  Linux mount point (`losetup` + `mount -o ro`); only OS built-ins
- **serve** the disk or a partition **read-only over NBD** (`serve`), and
  **connect** to that export with the **built-in NBD client** (`connect`) —
  on Linux it becomes a real `/dev/nbdN` block device you can `mount -o ro`
  with **no `nbd-client` binary needed**; on any OS you can `--pull` the
  export to a raw file or inspect its partitions over the wire

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
| EWF / Expert Witness `E01` | ✅ EWF v1 (`EVF`), stored + zlib chunks, single or multi segment; reads case metadata |
| VHD | ✅ fixed and dynamic (`conectix` / `cxsparse`, BAT + block bitmaps) |
| VMDK | ✅ monolithic & split **sparse** (`KDMV`), **flat** extents via the descriptor; stream-optimized (compressed) is detected and rejected with a message |
| VHDX | ⚠️ detected only — convert it to raw first, or attach it in Windows |

The format is sniffed from the header (and the VHD footer); `--format` forces
it.

## Partition tables

MBR (including extended / logical partitions) and GPT (via the protective
MBR), with type-code → label mapping for the common filesystem, LVM, RAID,
EFI and Apple GUIDs. `partitions --json` emits `start_offset` / `start_lba` /
`length` for every partition — feed those offsets to `windows_mft`,
`recovery_metadata`, etc.

---

## Mount as a read-only drive

```bash
# Windows (run from an elevated / Administrator shell)
mounting_image mount disk.E01 --letter X
#   materialises a temp fixed VHD, Mount-DiskImage -Access ReadOnly,
#   assigns X: (and auto-letters the other volumes); Explorer opens it read-only

# Linux (root)
mounting_image mount disk.E01 --partition 2 --mountpoint /mnt/evidence --fstype ntfs

# macOS
mounting_image mount disk.E01                 # hdiutil attach -readonly

mounting_image drives                          # what's mounted
mounting_image unmount-drive X:                # detach (letter, mount point, or id)
```

| Switch | |
|---|---|
| `--letter X` | Windows: drive letter to assign |
| `--partition N` | which partition gets the letter / mount |
| `--mountpoint DIR` | Linux/macOS mount directory |
| `--fstype` | Linux filesystem type (`ntfs`, `ext4`, …) |
| `--image-out PATH` | keep the materialised VHD/raw (else a temp file, removed on unmount) |

Windows and macOS need a materialised file (a fixed VHD / raw), so `mount`
writes one first — a full-size copy — unless the source already is one. On
Linux the NBD path (`serve --attach` / `connect --attach`) avoids the copy.
`Mount-DiskImage` requires an **elevated** PowerShell session.

---

## Serving and connecting over NBD

`serve` runs a minimal read-only NBD server (fixed-newstyle handshake;
`READ` / `FLUSH` / `DISCONNECT`; `WRITE` and `TRIM` return `EPERM`).
`connect` is the matching **built-in client** — no `nbd-client` binary.

### All-in-one (Linux, as root)

```bash
mounting_image serve disk.E01 --partition 2 --attach --run \
    --nbd-device /dev/nbd0 --mountpoint /mnt/evidence
# starts the server, attaches it to /dev/nbd0 via the kernel 'nbd' module,
# mounts it read-only, and holds the connection until Ctrl-C.
# (run 'modprobe nbd' once first so /dev/nbd* exists)
```

### Two steps / two machines

```bash
# machine A - export partition 2
mounting_image serve disk.E01 --partition 2 --port 10809 --name evidence

# machine B (Linux, root) - attach + mount with the built-in client
mounting_image connect nbd://A:10809/evidence --attach \
    --device /dev/nbd0 --mountpoint /mnt/evidence
```

### Any OS - no kernel NBD

```bash
mounting_image connect nbd://host:10809/evidence --partitions      # inspect
mounting_image connect nbd://host:10809/evidence --pull disk.raw   # download
mounting_image partitions nbd://host:10809/evidence                # URL as a source
```

`nbd://host:port/export` works anywhere an image path does (`info`,
`partitions`, `convert`, `extract`, `cat`). `mounting_image list` shows
attached sessions; `mounting_image unmount --port 10809 --run` unmounts and
disconnects the device in-process.

---

## GUI

```bash
mounting_image gui            # then Browse → Open
mounting_image gui disk.E01
```

Container summary, a partition table, and buttons to **export the selected
partition (or whole disk) to raw**, **copy a partition's start offset**,
**toggle a local NBD export**, and **mount as a read-only drive** — on
Windows with a drive-letter dropdown (free letters only); on Linux/macOS it
prompts for a mount point. Unmount from the same button.

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
- **Off-host.** Pure Python parsing — no external EWF library, no loop devices
  needed to read.

---

## Status

raw / split / EWF-v1 / VHD / VMDK-sparse / VMDK-flat and MBR / GPT are parsed
and covered by the test suite, which builds a synthetic image in each format
and checks a full byte round-trip (the dev box has no real acquired images —
validation against independent EWF / VMDK readers is a to-do). The NBD **server
and client** protocol paths are tested over loopback; the Linux
`/dev/nbdN` kernel-attach path is not unit-tested (no Linux on the dev box).
Not yet done: VHDX, EWF v2 (`Ex01`), compressed/stream-optimized VMDK, AFF4,
`.vdi`, APFS / LVM container mapping (planned as `mounting_partitions`), and a
FUSE / WebDAV mount so a partition's filesystem appears as a browsable folder
on Windows / macOS. See the project roadmap.
