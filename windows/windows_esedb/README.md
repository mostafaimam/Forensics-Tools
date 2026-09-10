# windows_esedb

**A from-scratch ESE / JET (`.edb`) reader — no libesedb, no dependencies.**
`windows_esedb` parses the Extensible Storage Engine database format that
Windows uses for SRUM (`SRUDB.dat`), the WinINET cache (`WebCacheV01.dat`),
the User Access Log (`*.mdb`), Windows Search (`Windows.edb`) and more. It is
the engine behind [`windows_srum`](../windows_srum), [`windows_webcache`](../windows_webcache)
and [`windows_usbdevices`](../windows_usbdevices), and works standalone.

What it does:

- reads the database header — page size, format version / revision, clean /
  dirty state;
- parses the **catalog** (`MSysObjects`) into tables, columns (type, size,
  code page) and long-value trees;
- walks the **B-tree** of any table from its FDP page (with a sibling-chain
  fallback for a damaged branch page);
- decodes leaf records via the **fixed / variable / tagged** data layout,
  including the Vista+ extended tagged format (separated long values,
  multi-values), the null bitmap and 7-bit text compression;
- assembles long values from the long-value B-tree;
- converts OLE-automation dates and (on request) FILETIME columns.

## Usage

```
windows_esedb SRUDB.dat --info
windows_esedb SRUDB.dat --list-tables
windows_esedb WebCacheV01.dat --table Containers --csv containers.csv
windows_esedb SRUDB.dat --table '{DD6636C4-8929-4683-974E-22C046A43763}' \
    --filetime-columns ConnStartTime --json net.json
```

| flag | effect |
|------|--------|
| `--info` | header + catalog summary (the default with no other action) |
| `--list-tables` (`--all-tables`) | table names (add the `MSys*` internals) |
| `--table NAME` | dump every row of a table |
| `--filetime-columns a,b` | render these integer columns as FILETIME |
| `--limit N` | stop after N rows |
| `--csv PATH` / `--json PATH` | write the table (`bytes` values as hex) |

## Why it separate

ESE is the single most common "I can't read this without a third-party
library" format in Windows DFIR. Pulling it into one vendored, zero-dependency
package means every ESE-backed artefact tool in the suite stays self-contained
and cross-platform.

## Limitations (v0.1)

- **Long-value compression.** 7-bit compression is handled; the `XPRESS` /
  `LZXPRESS`-Huffman compression used for some large `Windows.edb` long
  values is not yet inflated — such a value is returned as its raw
  compressed bytes.
- **Dirty databases.** A database that was not cleanly shut down is read
  best-effort (the tool flags it); transaction-log (`.jfm` / `edb*.log`)
  replay is not performed. Run the DB through `esentutl /r` on a Windows box
  first if it will not open, or accept the best-effort read.
- **Indexes and space trees** are skipped — only the primary data B-tree and
  the long-value tree of each table are read.
- Multi-value tagged columns return the first value.
- Written and tested against the format; **not yet validated against a real
  Microsoft `SRUDB.dat` / `WebCacheV01.dat`** on this dev box.

## Tests

```
cd windows/windows_esedb && python -m pytest -q
```

`tests/_ese_synth.py` hand-builds a well-formed legacy-format ESE database
(4 KiB pages, a catalog and an `Events` table with fixed `Long` / `DateTime`
/ `LongLong` columns, a variable `Text` column and a tagged `LongText`
column) and the tests check the header, catalog parse, the B-tree walk, the
record decode (including the tagged value and the OLE date) and the CLI.
