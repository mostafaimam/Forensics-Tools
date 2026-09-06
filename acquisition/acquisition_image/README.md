# acquisition_image

**Create and verify forensic disk images.** Reads a source — a file, a
partition/volume, or a whole physical disk — and writes a forensically sound
image, hashing every byte as it goes, tolerating bad sectors, and producing an
acquisition log, a JSON manifest and an HTML report. A separate verification
pass re-reads the written image and compares hashes.

![The `acquisition_image gui` wizard](docs/screenshot.png)

| Output format | |
|---|---|
| `raw` | a single `dd`-style file |
| `split` | raw split into `NAME.001`, `NAME.002`, … at a chosen size |
| `ewf` / `e01` | EWF v1 (`E01`) — zlib-compressed 32 KiB chunks, `.E01/.E02/…` segments, embedded case metadata + MD5/SHA-1 digest sections |

MD5 + SHA-1 + SHA-256 are computed in one streaming pass. Unreadable sectors
are retried, then zero-filled and recorded (offset + length) in the log —
the acquisition continues.

CLI and a **tkinter wizard** (`acquisition_image gui`). Zero third-party
dependencies.

```
acquisition_image disks
acquisition_image acquire /dev/sdb evidence.E01 --format ewf \
    --case 2026-014 --examiner "A. Analyst" --verify
acquisition_image acquire disk.dd out.raw --split 2G
acquisition_image verify evidence.E01
acquisition_image hash /dev/sdb
```

---

## Install

Requires **Python 3.11+** (`tkinter` for the wizard). Reading a raw disk
device needs privileges (root / Administrator).

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/acquisition/acquisition_image
pip install -e .
```

---

## Usage

### `disks` — what can I image?

```bash
acquisition_image disks
#  /dev/sda                 500.1 GB  Samsung SSD 860
#      /dev/sda1
#      /dev/sda2
#  \\.\PHYSICALDRIVE1        64.0 GB  SanDisk Ultra  [removable]
```

Linux reads `/sys/block`; macOS shells `diskutil list -plist`; Windows uses
`Get-CimInstance Win32_DiskDrive`.

### `acquire` — image a source

```bash
acquisition_image acquire \
    \\.\PHYSICALDRIVE1 \
    /evidence/2026-014.E01 \
    --format ewf --compression fast --segment-size 4G \
    --case 2026-014 --evidence "USB-3" --examiner "A. Analyst" \
    --description "SanDisk Ultra 64GB" --verify
```

| Switch | |
|---|---|
| `--format raw\|split\|ewf` | output container (default `raw`) |
| `--split SIZE` | raw: segment size (`2G`, `650M`, `1500000`); implies `--format split` |
| `--segment-size SIZE` | ewf: roll to a new `.E0x` at this size |
| `--compression none\|fast\|best` | ewf chunk compression (default `fast`) |
| `--sector-size N` | source sector size (default 512) |
| `--offset` / `--length` | image only part of the source (`SIZE` suffixes allowed) |
| `--verify` | re-read the written image and compare hashes |
| `--case` / `--evidence` / `--examiner` / `--description` / `--notes` | case metadata (also embedded in the EWF header) |

Three sidecar files are written next to the image (`<image>.txt`, `.json`,
`.html`): the acquisition log, a machine-readable manifest, and an HTML
report showing acquisition vs verification hashes and any bad regions.

### `verify` — check an image later

```bash
acquisition_image verify 2026-014.E01                 # vs its embedded digest
acquisition_image verify out.raw --md5 <known-md5>    # vs a known hash
acquisition_image verify img.raw                      # split set: pass the .001 or the stem
```

### `hash` — hash a source without imaging

```bash
acquisition_image hash /dev/sdb
```

---

## How it works

- **One read path.** `Source` gives a size-known, seekable view of a file, a
  Linux `/dev/*` block device (size from `/sys/block/<d>/size`), or a Windows
  `\\.\PhysicalDriveN` (size via `IOCTL_DISK_GET_LENGTH_INFO`). A read error
  drops to sector-by-sector: retry, then zero-fill and record the range.
- **Streaming hashes.** The source is read once in 1 MiB blocks; MD5 / SHA-1 /
  SHA-256 update as the bytes flow to the writer.
- **EWF writer.** `header` + `header2` (case metadata), a `volume` section
  (geometry), then `sectors` / `table` / `table2` per segment with
  zlib-compressed or stored 32 KiB chunks, and `digest` (MD5 + SHA-1) +
  `hash` (MD5) sections at the end. 31-bit chunk-offset limits and
  `--segment-size` are handled by starting new table / segment boundaries.
  A non-sector-aligned source is zero-padded to a sector and the padding is
  noted.
- **Verification** re-reads the finished image (decompressing EWF chunks) and
  compares the recomputed hashes to the acquisition hashes and, for EWF, to
  the digest stored inside the file.

---

## Design choices

- **Read-only source, write-once image.** The source is opened `rb`.
- **UTC**, ISO-8601 timestamps in the log and manifest.
- **Never abort on a bad sector** — zero-fill, log, keep going; the result is
  flagged "review".
- **Independently verifiable** — the `E01` is plain EWF v1 and opens in
  `mounting_image`, `libewf` (`ewfverify`), FTK Imager, X-Ways, etc.

---

## Status

raw / split / EWF-v1 write + verify, streaming triple-hash, bad-sector
handling, and disk enumeration are covered by the test suite (a synthetic
"disk" is imaged in every format and checked for a byte-exact round trip;
the `E01` is also re-read by the independent `mounting_image` parser). Not
yet done: EWF v2 (`Ex01`), `AFF4`, in-acquisition compression tuning by
entropy, resumable acquisition, and remote (SSH/iSCSI) sources. See the project roadmap.
