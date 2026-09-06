# memory_strings

**Address-aware string extraction from a RAM dump.** Pulls ASCII and UTF-16LE
string runs out of a physical-memory dump (raw / LiME / ELF core / Windows
crash dump), tags each with the **physical address** it was found at, and
classifies it against a built-in pattern library.

![`memory_strings gui`](docs/screenshot.png)

```
memory_strings scan mem.lime --classified --csv iocs.csv
memory_strings scan mem.lime --category url,email,btc,powershell
memory_strings scan mem.lime --grep 'password' --min-len 6
memory_strings scan MEMORY.DMP --physical-from 0x1000000 --physical-to 0x2000000
memory_strings categories
```

Zero third-party dependencies (vendors `memory_image`'s loader).

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/memory/memory_strings
pip install -e .
```

---

## Usage

`scan` streams the dump's physical runs, finds printable runs ≥ `--min-len`
(default 6) in ASCII and UTF-16LE, and emits `phys`, `encoding`, `length`,
`category`, `match`, `text`.

| Switch | |
|---|---|
| `--classified` | keep only strings that match a pattern |
| `--category C,C` | keep only these pattern categories |
| `--grep REGEX` | keep only strings matching (case-insensitive) |
| `--min-len N` | minimum run length (default 6) |
| `--ascii-only` / `--unicode-only` | one encoding |
| `--physical-from` / `--physical-to` | limit to a physical range |
| `--limit N` | stop after N hits |
| `--csv` / `--json` | output files |

### Pattern library

`url`, `email`, `ipv4`, `ipv6`, `hostname`, `unc_path`, `win_path`,
`unix_path`, `registry`, `guid`, `powershell`, `cmdline`, `base64_blob`,
`private_key`, `aws_key`, `jwt`, `btc`, `eth`, `credit_card` (Luhn-checked),
`user_agent`, `sql`. `memory_strings categories` lists them.

---

## How it works

Strings are found per physical run and their address is `run.phys_start +
match offset`. There is **no virtual-address translation** — that needs the
page tables and is a job for the structural analysis tools; `memory_strings`
tells you *where in physical memory* a hit lives, which is enough to carve the
surrounding region (`memory_image carve`) or narrow a `--physical-from/-to`
sweep.

---

## Status

ASCII + UTF-16LE extraction, physical-address tagging, the pattern library
(Luhn-validated cards) and all the filters are covered by the test suite
(synthetic LiME dumps). Not yet done: gzip/zlib-inflate of compressed regions
before scanning, stacked-string / XOR-brute heuristics, and per-process
attribution (needs the analysis tools). See the project roadmap.
