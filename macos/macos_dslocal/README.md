# macos_dslocal

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse local account records from /var/db/dslocal.**

Reads the Directory Services local node (`/var/db/dslocal/nodes/Default`) — user
and group plists — for account inventory: uid / gid, home, shell, real name,
`ShadowHashData` presence (never output), admin-group membership, and creation
date.

## Planned scope

- Parse the account plists; decode `accountPolicyData`,
  `authentication_authority`
- Group membership resolution; admin / _lpadmin / wheel flags
- Flag hidden users (uid < 500), recently created accounts, disabled password
  policy
- CSV / JSON

## Inputs

`/var/db/dslocal/nodes/Default/{users,groups}/*.plist`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_plist`, `linux_persistence`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
