# Forensics Tools

An open-source, cross-platform suite of DFIR command-line tools — written in
Python (3.11+, standard library only) and built to run on Windows, Linux and
macOS.


## Tools

| Tool | Status | Purpose |
|---|---|---|
| [**trace-collect**](trace-collect/) | ✅ v0.1 | Targeted artefact **acquisition** from a live system or mounted image — locked-file handling, Volume Shadow Copy, streaming hashes, chain-of-custody manifest |
| [**trace-recycle**](trace-recycle/) | ✅ v0.1 | Recover deletion metadata from Vista+ `$I` records and the legacy `INFO2` / `INFO` index; match `$R` / `Dc` content; CSV / JSON |
| [**trace-prefetch**](trace-prefetch/) | ✅ v0.1 | Decode Windows Prefetch (`.pf`) versions 17-31, including the Windows 10/11 `MAM` / XPRESS-Huffman compressed format (pure-Python decompressor) |
| **trace-mft** | 🔜 planned | Parse the NTFS `$MFT`, `$UsnJrnl:$J`, `$Boot` and `$Secure:$SDS` into a timeline (CSV / JSON) |
| **trace-evtx** | 🔜 planned | Parse Windows event logs (`.evtx`) with field extraction and filtering |

See [BACKLOG.md](BACKLOG.md) for the full roadmap (timeline tooling,
Linux/macOS artefact parsers, imaging / FTK-equivalent capabilities).

## Design principles

- **Zero runtime dependencies** — drops onto an unknown host with just Python.
- **UTC everywhere** — ISO-8601 with a `Z` suffix, no local-time ambiguity.
- **Cross-platform** — Windows-first artefacts, but Linux/macOS are first-class.
- **Long paths & Unicode** — `\\?\` extended paths on Windows, UTF-8(-BOM) CSV.
- **Forensically sound output** — deterministic, hashed, with a machine- and
  human-readable manifest for chain of custody.

## Getting started

```bash
cd trace-collect
python -m trace_collect --list-targets
python -m trace_collect -d ./out --dry-run
```

See each tool's own `README.md` for full usage and internals.

## License

MIT — see [LICENSE](LICENSE).
