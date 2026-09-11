# windows_sigma

**Sigma-shaped detection rules, run against this suite's own output.**

`windows_sigma` is a small, self-contained detection-rules engine: it reads
Sigma-style YAML rules and evaluates them against the normalised CSV / JSON
that `windows_evtx` and `windows_pslogging` already produce, turning a
sea of parsed events into a short list of prioritised hits.

## What it supports

- **A hand-rolled YAML reader** (`yamlmini.py`) covering the subset Sigma
  rules actually use: block mappings, block lists, inline `[a, b]` lists,
  quoted / bare scalars. No anchors, tags, or multi-line folded scalars —
  keep rule text (like `description`) on one line.
- **The detection grammar**: named selections plus a `condition`
  expression with `and` / `or` / `not`, parentheses, and the aggregate
  forms `1 of <name>` / `all of <name>` / `<n> of <name*>` (wildcards
  match selection names by prefix).
- **Field modifiers**: `|contains`, `|startswith`, `|endswith`, `|re`,
  `|all` (require every value in a list to match, instead of any); a bare
  value with `*` / `?` is matched as a glob, otherwise exact
  (case-insensitive).
- **A bundled starter ruleset** (5 rules): encoded/download-cradle
  PowerShell, event-log cleared (1102/104), a LOLBin-with-suspicious-args
  process pattern, new-service installed (7045/4697), and a credential
  -dumping / LSASS-access pattern spanning both PowerShell and process
  command lines.

## Usage

```
windows_sigma evtx.csv --csv hits.csv
windows_sigma pslog.csv evtx.csv --rule-dir ./my_rules
windows_sigma evtx.json --min-level high
windows_sigma --list-rules
```

| flag | effect |
|------|--------|
| `--rule FILE` | one extra rule file; repeatable |
| `--rule-dir DIR` | a directory of `*.yml` rules; repeatable |
| `--no-bundled` | skip the starter ruleset (use only `--rule` / `--rule-dir`) |
| `--list-rules` | print every loaded rule + its condition and exit |
| `--min-level info\|low\|medium\|high\|critical` | drop hits below this level |
| `--csv PATH` / `--json PATH` | `rule, rule_id, level, tags, time, matched, source` |

Exit code is non-zero when a `high` or `critical` hit is present.

## Field sources

A row from `windows_evtx` exposes `EventID` (aliased from `EventId`),
`Channel`, `Provider`, `Computer`, `TimeCreated`, plus **every named field
in its parsed `Payload`** (Sysmon's `Image` / `CommandLine` /
`TargetFilename`, Security's `SubjectUserName` / `TargetUserName`, and so
on — whatever the event actually carries). A row from `windows_pslogging`
exposes `ScriptBlockText`, `ScriptBlockId`, `User`, `Computer`, `Path`,
`HostApplication`, aliased from that tool's own columns. Rules that
reference a field neither source has simply do not match that row's
selection.

## Logsource matching

Matching a Sigma `logsource` to which of the suite's outputs a row came
from is **best-effort**: `service: security` / `system` / `sysmon` is
matched against the `Channel` column; `service: powershell` matches
`windows_pslogging` rows; a rule with no `service` / `category` at all is
tried against every row regardless of source. There is no formal Sigma
logsource taxonomy here — if a rule's fields do not appear in a row, its
selections simply evaluate false.

## Why it matters

Every `windows_evtx --csv` export or `windows_pslogging` run produces
thousands of rows; a detection rule is how you turn "here is the log" into
"here is the thing that matters." Because rules are plain YAML files, an
examiner can add a rule for a case-specific IOC or TTP in two minutes
without touching Python, and the same rule works unchanged the next time
that pattern shows up.

## Limitations (v0.1)

- This is **not** a full Sigma implementation: no `|base64offset`, no
  timeframe/near correlation, no field-to-field comparisons, no
  aggregation (`count() by`), and selection values must be a mapping (a
  list of alternative mappings for one selection is not yet supported).
  A rule using an unsupported feature either loads with reduced meaning
  or fails to parse — check `--list-rules` after adding a new rule.
- The YAML reader rejects multi-line plain/folded scalars outright (with
  a clear error) rather than mis-parsing them; write single-line values.
- Real-world Sigma rules aimed at Sysmon / Elastic / Splunk field names
  will only fire on the fields this suite's parsers actually expose in
  `Payload` — many upstream rules will need light adaptation.
- No de-duplication across overlapping rules; a row matching two rules
  produces two hits.

## Tests

`tests/_synth.py` builds `windows_evtx`- and `windows_pslogging`-shaped
CSVs (an 1102 log-clear, a Sysmon `certutil -urlcache` LOLBin process, an
`-enc` PowerShell script, an `Invoke-Mimikatz sekurlsa` script, and
benign rows that must **not** match). The tests cover the mini-YAML
reader, the condition tokenizer/parser/evaluator (`and`/`not`/`1 of`),
loading the bundled ruleset with zero errors, all five bundled rules
firing on their targets and not on benign rows, `--min-level` filtering,
a custom `--rule-dir` rule, `--list-rules`, and the CLI CSV(BOM) / JSON
output with the correct non-zero exit code.

```
cd windows/windows_sigma && python -m pytest -q
```
