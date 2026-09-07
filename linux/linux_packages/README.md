# linux_packages

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Reconstruct package install / upgrade / remove history.**

Parses dpkg / apt and rpm / dnf / yum history into one normalised timeline of
package events: action, package, version, date, and (where recorded) the
requesting user and command line.

## Planned scope

- dpkg / apt text log grammar; rpm and dnf history database reads
- Normalise to (timestamp, action, package, version, user, tool)
- Flag out-of-repo installs, downgrades, compiler / toolchain additions
- Timeline + JSON

## Inputs

`/var/log/dpkg.log*`, `/var/log/apt/history.log*`, `/var/lib/rpm`,
`/var/lib/dnf/history*`, `/var/log/yum.log*`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_syslog`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
