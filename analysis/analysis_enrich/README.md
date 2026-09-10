# analysis_enrich

**Add the context columns to a timeline — without touching the rows.**

`analysis_enrich` takes an `analysis_timeline` bundle (CSV / JSON / JSONL)
and **appends** columns. Every original field and the row order are kept;
each enricher only adds.

| added column(s) | enricher |
|-----------------|----------|
| `ioc`, `ioc_type`, `ioc_source` | IPs / IPv6 / domains / URLs / MD5 / SHA-1 / SHA-256 found in the row, matched against supplied feeds (plain list, CSV, or STIX-lite JSON). Domain matches also fire on a parent-domain suffix. |
| `attack`, `attack_name` | MITRE ATT&CK technique ids from a **bundled map** (~30 entries) keyed by the tool / artefact / command patterns the suite emits — `schtasks /create` → T1053.005, `-enc <b64>` → T1059.001 + T1027, `wevtutil cl` → T1070.001, `Net.WebClient` → T1105, `sekurlsa` → T1003.001, … |
| `geo` | a coarse **registry region** (ARIN / RIPE / APNIC / LACNIC / AFRINIC) for each public IPv4, from a bundled first-octet table — or precise labels from a `--geo-csv` of `cidr,label` |
| `known` | `good` / `bad` / `<label>` for hashes, from a `--known-csv` (e.g. an `analysis_kff` export) |

## Usage

```
analysis_enrich timeline.csv --feed iocs.txt -o timeline.enriched.csv
analysis_enrich tl.jsonl --feed c2.csv --feed hashes.json \
    --known-csv kff.csv -o tl.enriched.jsonl
analysis_enrich timeline.csv --no-attack --geo-csv geoip.csv -o out.csv
```

| flag | effect |
|------|--------|
| `--feed FILE` | an IOC feed; repeatable. Plain list (one per line), CSV (`indicator[,type][,source]`), or STIX-lite JSON (`{"indicators":[…]}` with `pattern` or `value`) |
| `--geo-csv FILE` | a `cidr,label` table used before the built-in RIR table |
| `--known-csv FILE` | a `hash,label` list |
| `--no-attack` | skip ATT&CK tagging |
| `-o` / `--out` | the enriched output (same format as the input) — **required** |

The console summary prints the IOC / ATT&CK hit counts and the top
techniques seen, so it doubles as a quick "what's in this timeline" view.

## Why it matters

A merged super-timeline is thousands of rows. Enrichment is what makes it
*searchable by meaning*: filter to `attack` contains `T1003` for
credential access, to `ioc_source` = your threat feed's name for
attributed activity, to `known` = `bad` for confirmed malware. Because it
only appends, you can run it repeatedly with new feeds as an
investigation develops, and hand the result straight to `analysis_view`
or `analysis_report`.

## Limitations (v0.1)

- The ATT&CK map is a **curated pattern list**, not the full framework —
  it covers what this suite's parsers surface. Tags are hints for
  triage / reporting, not authoritative technique attribution.
- Geolocation is **registry-region only** from a compact bundled table
  (no city, and the first-octet allocations are approximate). For real
  geolocation supply `--geo-csv` from a MaxMind-style export.
- IOC extraction is regex-based over the row text; it will miss
  defanged indicators (`hxxp://`, `1[.]2[.]3[.]4`) and can pick up
  file-name "domains" — obvious ones (`.dll`, `.exe`, …) are filtered.
- Feed matching is exact (case-insensitive) on the indicator value, plus
  domain-suffix; no fuzzy or CIDR matching of feed IPs yet.
- `known` only marks hashes present in `--known-csv`; there is no bundled
  hash set (use `analysis_kff` and export one).

## Tests

`tests/test_analysis_enrich.py` covers indicator extraction, the ATT&CK
tagger (including the `-enc` → T1059.001 + T1027 combo), the RIR-region
lookup and private-IP handling, all three feed formats, a full enrichment
of a 3-row timeline (IOC + source + ATT&CK + geo + known-bad hash), and
the CLI CSV(BOM) and JSONL round trips.

```
cd analysis/analysis_enrich && python -m pytest -q
```
