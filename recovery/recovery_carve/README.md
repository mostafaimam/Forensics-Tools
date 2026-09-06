# recovery_carve

**File recovery by magic-byte signature carving** with structural validators.

Recovers files from a raw image, a device, or a blob of unallocated space
**even when the file-system metadata is gone** — the header/footer bytes and,
where possible, the internal structure of each format are used to find and
size each object exactly.

```
recovery_carve disk.dd -o carved/
recovery_carve unalloc.bin -o out/ --types jpg,png,pdf --hash md5,sha1
recovery_carve image.raw -o out/ --category image,document --manifest-only
```

Zero third-party dependencies, cross-platform.

---

## recovery_carve vs recovery_metadata

The `recovery/` category has two complementary tools:

| | **recovery_carve** (this tool) | [**recovery_metadata**](../recovery_metadata/) |
|---|---|---|
| Finds files by | content signature (magic bytes + structure) | file-system metadata (`$MFT`, directory entries) |
| Needs an intact file system | no | yes |
| Recovers original **names / paths** | no | yes |
| Recovers **timestamps** | no | yes (`MACB`, `$SI` + `$FN`) |
| Recovers files in **unallocated space** with no metadata | yes | no |
| Recovers **deleted** files | yes (if bytes present) | yes (if clusters not reallocated) |

Use `recovery_carve` when the file system is damaged or you are working on raw
unallocated space; use `recovery_metadata` when the file system is intact and
you want names and timelines. They are often run together.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/recovery/recovery_carve
pip install -e .
```

---

## Usage

```bash
recovery_carve --list-signatures

# carve everything
recovery_carve disk.dd -o carved/

# only some types / categories
recovery_carve disk.dd -o out/ --types jpg,png,sqlite
recovery_carve disk.dd -o out/ --category image,archive

# index only, don't write recovered files
recovery_carve disk.dd -o out/ --manifest-only

# also carve objects nested inside other carved objects (zip-in-zip, etc.)
recovery_carve disk.dd -o out/ --nested
```

| Switch | Effect |
|---|---|
| `-o DIR` | output directory (`carved/` + `recovery_carve_manifest.csv`) |
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

Adding a signature is a one-line entry in `recovery_carve/signatures.py`, plus
an optional validator in `recovery_carve/validators.py`.

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
