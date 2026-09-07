# macos_fsevents

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse /.fseventsd file-system change records.**

Decodes the gzipped FSEvents logs into a file-system change timeline: path,
change flags (created / removed / renamed / modified / xattr), and event id
ordering — evidence of file activity even after the files are gone.

## Planned scope

- Gzip member iteration; DLS1 / DLS2 record formats
- Change-flag decoding; event-id monotonic ordering
- Approximate timestamps by correlating event ids with other artefacts
- Bodyfile + JSON

## Inputs

`/.fseventsd/*` (per volume), or carved fseventsd records.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_unifiedlog`, `recovery_fs`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
