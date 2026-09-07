# utilities_ole

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**OLE2 / compound-file and Office metadata extraction.**

A standalone OLE2 (Compound File Binary) reader and Office document metadata /
structure extractor: stream tree, `SummaryInformation` /
`DocumentSummaryInformation`, embedded objects and macros, and OOXML core / app
/ custom properties.

## Planned scope

- CFB header, FAT / miniFAT, directory tree, stream extraction
- Property-set parsing (author, dates, template, last-saved-by, revision)
- VBA project detection + macro source extraction; embedded-object listing
- Shared library the other tools import

## Inputs

`.doc` / `.xls` / `.ppt` / `.msg` / other OLE2 files; OOXML `.docx` / `.xlsx` /
`.pptx`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`analysis_email`, `windows_jumplist`, `analysis_search`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
