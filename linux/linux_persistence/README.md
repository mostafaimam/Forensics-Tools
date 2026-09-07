# linux_persistence

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**One sweep for every userland persistence vector on Linux.**

Aggregates every common persistence mechanism into a single review: shell rc /
`profile.d` / `/etc/environment`, `ld.so.preload` / `ld.so.conf` / `LD_*`, cron
/ at, systemd generators and `.service` drop-ins, udev rules, `motd` /
`update-motd.d`, `rc.local`, xinetd, PAM modules, and kernel-module autoload.

## Planned scope

- Delegates to `linux_cron` / `linux_units` where those exist; covers the rest
  directly
- One normalised finding row: mechanism, path, payload, owner, mtime, verdict
- Flag world-writable configs, non-package files in package-owned dirs, encoded
  payloads
- HTML / JSON report

## Inputs

A mounted Linux image or live system.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_cron`, `linux_units`, `linux_sshkeys`, `analysis_report`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
