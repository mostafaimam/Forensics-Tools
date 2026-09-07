# linux_audit

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Normalise auditd audit.log records.**

Parses the Linux audit daemon logs — reassembling multi-line events by
`msg=audit(…)` id — into normalised rows: syscall, exe, proc title, uid / auid,
keys, path items, and outcome; decodes hex-encoded fields.

## Planned scope

- Group records by event id; decode `proctitle`, `cmd`, `path` hex fields
- Map syscall numbers to names per architecture
- Event-type views: EXECVE, USER_AUTH, USER_CMD, PATH, AVC (SELinux)
- Timeline + security-event output

## Inputs

`/var/log/audit/audit.log*` (+ rotated / `.gz`).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_journal`, `linux_syslog`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
