# windows_wmi

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the WMI repository for persistence (OBJECTS.DATA / INDEX.BTR).**

Reads the WMI CIM repository and reconstructs event-subscription persistence:
`__EventFilter`, `CommandLineEventConsumer` / `ActiveScriptEventConsumer`, and
the `__FilterToConsumerBinding` that ties them together — a classic fileless
persistence mechanism.

## Planned scope

- Parse the repository page format, the index B-tree, and class definitions
- Extract filter queries, consumer command lines / script text, bindings
- Flag script consumers, encoded payloads, non-default namespaces
- Timeline from the object timestamps where present

## Inputs

`C:\Windows\System32\wbem\Repository\{OBJECTS.DATA,INDEX.BTR,MAPPING*.MAP}`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `windows_pslogging`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
