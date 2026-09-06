# trace-recover

**File recovery by magic-byte signature carving** with structural validators.

Recovers files from a raw image, a device, or a blob of unallocated space
**even when the file-system metadata is gone** — the header/footer bytes and,
where possible, the internal structure of each format are used to find and
size each object exactly.

```
trace-recover disk.dd -o carved/
trace-recover unalloc.bin -o out/ --types jpg,png,pdf --hash md5,sha1
trace-recover image.raw -o out/ --category image,document --manifest-only
```

Zero third-party dependencies, cross-platform.

---

## What it does — and doesn't (yet)

| | trace-recover v0.1 | planned |
|---|---|---|
| Carve files by content signature (no file system needed) | ✅ | |
| Structural sizing (SQLite page count, ZIP EOCD, PNG chunks, JPEG marker walk, GZIP inflate, BMP header, …) | ✅ | |
| Recover file **names / paths / timestamps** from file-system metadata | ✗ | ✅ NTFS `$MFT`, FAT, ext4, APFS/HFS+ |
| Extract a single file by inode / MFT-entry number | ✗ | ✅ (`--entry`) |
| Extract *deleted-but-referenced* files with their original paths | ✗ | ✅ |

So today it is a signature carver — it finds the bytes when the metadata is
unrecoverable, but it cannot give you the original filename. Metadata-driven
recovery (walk the file system, extract files — including deleted ones — with
their names, paths and `MACB` times; pull a single file by MFT-entry / inode
number) is the next milestone; see [../BACKLOG.md](../BACKLOG.md).

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/trace-recover
pip install -e .
```

---

## Usage

```bash
trace-recover --list-signatures

# carve everything
trace-recover disk.dd -o carved/

# only some types / categories
trace-recover disk.dd -o out/ --types jpg,png,sqlite
trace-recover disk.dd -o out/ --category image,archive

# index only, don't write recovered files
trace-recover disk.dd -o out/ --manifest-only

# also carve objects nested inside other carved objects (zip-in-zip, etc.)
trace-recover disk.dd -o out/ --nested
```

| Switch | Effect |
|---|---|
| `-o DIR` | output directory (`carved/` + `trace-recover_manifest.csv`) |
| `--types ID,ID` / `--category C,C` | limit signatures (`--list-signatures` for the set) |
| `--hash md5,sha1,sha256` | digests recorded per object (default `sha1`) |
| `--min-size` / `--max-size` | size bounds (`--max-size` caps every signature) |
| `--nested` | don't skip hits that fall inside an already-carved object |
| `--max-per-type N` | stop after N objects of each type |
| `--manifest-only` | write the CSV but not the files |

---

## Manifest columns

`index`, `offset`, `length_bytes`, `end_offset`, `type`, `category`,
`extension`, `confidence`, `truncated`, `md5`, `sha1`, `output_path`

`confidence` is one of:

| value | meaning |
|---|---|
| `structure` | the format's own structure gave an exact length (most reliable) |
| `footer` | terminated at the first valid trailer signature |
| `header-only` | no footer / structure found; carved up to the size cap (`truncated=yes` if the cap was hit) |

---

## Signatures

`--list-signatures` prints the current set. Structurally-validated types are
marked `[validated]`:

- **images** — JPEG (marker walk), PNG (chunk walk), GIF (block walk), BMP
  (header size), TIFF
- **documents** — PDF (`%%EOF`), OLE2 / legacy Office
- **archives** — ZIP / OOXML / JAR / APK (End-Of-Central-Directory), GZIP
  (inflate to EOF), RAR, 7-Zip
- **databases** — SQLite 3 (page size × page count)
- **logs / registry** — EVTX (chunk count), registry hive (`regf` hbins size)
- **other** — Outlook PST/OST, LNK, NTFS `FILE` record, MP4/QuickTime,
  ELF, PE/MZ

Adding a signature is a one-line entry in `trace_recover/signatures.py`, plus
an optional validator in `trace_recover/validators.py`.

---

## How it works

```
open image ──► slide a 16 MiB window (with header-length overlap)
                   │
        one compiled multi-pattern regex of every header
                   │   for each hit:
                   ├─ validator?  → exact length from structure
                   ├─ footer?     → first trailing signature
                   └─ neither     → up to the size cap (flagged truncated)
                   │
        skip hits inside an already-carved object (unless --nested)
                   │
   stream each object to  carved/NNNNNN_<offset>_<type>.<ext>
   + a flushed-per-row manifest CSV (UTF-8 BOM, injection-safe)
```

Validated real-world check: six large Windows wallpaper JPEGs embedded in a
junk-padded blob are recovered at byte-exact lengths with matching SHA-1.

---

## Development

```bash
pip install pytest
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
