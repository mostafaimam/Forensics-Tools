# browser_shortcuts

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Omnibox typed-text → URL shortcuts and site-engagement data.**

Reads Chromium `Shortcuts` (what the user typed in the address bar and what they
picked), `Top Sites`, and the `Network Action Predictor` — strong evidence of
intent even when the visit itself was cleared.

## Planned scope

- Decode the `omni_box_shortcuts` schema: text, fill-into-edit, URL, hit count,
  last access
- Top Sites thumbnails + URLs; predictor hit / miss counts
- CSV / JSON; merge into the history timeline

## Inputs

Chromium `Shortcuts`, `Top Sites`, `Network Action Predictor` databases.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_history`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
