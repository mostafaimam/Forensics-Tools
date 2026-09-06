# recovery_metadata

**File recovery from file-system metadata.** Walk the file system of an image
or volume and list every entry — allocated *and* deleted — with its full path
and `MACB` timestamps, then extract file content, including
**deleted-but-not-overwritten** files.

v0.1 supports **NTFS** (`$MFT`). FAT / exFAT / ext2-4 / HFS+ / APFS are planned
— see the roadmap.

```
recovery_metadata list    volume.raw --csv mft.csv
recovery_metadata list    disk.dd --offset 1048576 --deleted-only
recovery_metadata extract volume.raw -o recovered/ --deleted-only
recovery_metadata cat     volume.raw --entry 41573 > file.bin
```

This is the metadata-driven counterpart to [`recovery_carve`](../recovery_carve/)
(signature carving): metadata gives you the **names, paths and timestamps**;
carving finds bytes when the metadata is gone.

Zero third-party dependencies, cross-platform — an NTFS image carved from any
host is analysed on Linux or macOS just the same.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/recovery/recovery_metadata
pip install -e .
```

---

## Usage

The image argument is a raw NTFS **volume** image, or a full **disk** image
with `--offset` pointing at the start of the NTFS partition (bytes).

### `list` — enumerate the MFT

```bash
recovery_metadata list volume.raw --csv mft.csv
recovery_metadata list disk.dd --offset 1048576 --deleted-only --files-only
```

| Switch | |
|---|---|
| `--csv FILE` | write the full listing |
| `--deleted-only` | only entries whose record is not in use |
| `--files-only` | skip directories |
| `--offset N` | byte offset of the NTFS volume in the image |
| `-q` | no console table |

CSV columns: `entry`, `sequence_state` (allocated / deleted), `type`, `path`,
`size_bytes`, `resident`, `fixup_ok`, and the `$STANDARD_INFORMATION` +
`$FILE_NAME` timestamps (`si_*_utc`, `fn_*_utc`) — all ISO-8601 UTC.

### `extract` — recover content to a tree

```bash
recovery_metadata extract volume.raw -o recovered/ --hash md5,sha1
recovery_metadata extract volume.raw -o recovered/ --deleted-only
```

Files land under `recovered/allocated/<path>` or `recovered/deleted/<path>`,
with a `recovery_metadata_extracted.csv` manifest (entry, state, path, output
path, size, hashes, note). NTFS system metadata files (entries &lt; 16) are
skipped.

### `cat` — one entry to stdout

```bash
recovery_metadata cat volume.raw --entry 41573 > recovered_file.bin
```

---

## How it works (NTFS)

```
boot sector (offset 0)
   bytes/sector · sectors/cluster · $MFT cluster · MFT record size
        │
$MFT record 0  → non-resident $DATA run list → full (possibly fragmented)
                 extent of the MFT itself
        │
for every 1 KiB MFT record:
   ├─ verify + apply the update-sequence-array fixup
   ├─ flags → in-use? directory?
   ├─ $STANDARD_INFORMATION → C/M/R/A FILETIMEs
   ├─ $FILE_NAME (prefer Win32 namespace) → name, parent entry, $FN times
   └─ unnamed $DATA → resident bytes, or a run list of clusters
        │
parent-entry chain → full path (root = entry 5)
        │
extract: resident content directly; non-resident content by reading the
         run-list clusters from the image (sparse runs → zeros)
```

A **deleted** file is simply a record whose in-use flag is clear; as long as
its `$DATA` run list still points at clusters that have not been reallocated,
`extract` / `cat` recover the original bytes.

---

## Design choices

- **UTC only**, ISO-8601 with a `Z` suffix; a zero `FILETIME` is blank.
- **Read-only.** The image is opened `rb`; nothing is ever written back.
- **Never crash.** A record with a bad signature, a failed fixup, or a
  malformed attribute is skipped (and flagged `fixup_ok=no` where relevant);
  the walk continues.
- **Both timestamp sets.** `$SI` and `$FN` times are reported separately so
  `$SI`-only timestomping is visible.

---

## Status

NTFS list / extract / cat are validated against a hand-built, byte-accurate
synthetic NTFS image (resident file, deleted non-resident file, path
resolution, fixup verification, run-list decoding). Testing against real
NTFS images is welcome. `--offset` auto-detection, `$ATTRIBUTE_LIST`
(very fragmented files), ADS extraction, and the other file systems are on
the backlog.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
