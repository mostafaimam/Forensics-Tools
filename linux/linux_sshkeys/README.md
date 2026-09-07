# linux_sshkeys

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Review SSH keys, known hosts and sshd configuration.**

Inventories every `authorized_keys` (system-wide and per-user), host keys,
`known_hosts` (including hashed entries), and reviews `sshd_config` /
`ssh_config` for risky settings — a focused look at SSH-based access and
persistence.

## Planned scope

- Parse authorized_keys options (command=, from=, no-pty), key type / comment /
  fingerprint
- Flag keys with forced commands, wildcard `from=`, weak / short keys
- sshd_config review: PermitRootLogin, PasswordAuthentication,
  AuthorizedKeysCommand
- known_hosts host inventory (attempt reversal of hashed entries against a
  supplied list)

## Inputs

A mounted Linux image or live system.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_persistence`, `linux_utmp`, `linux_syslog`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
