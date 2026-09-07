# linux_containers

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Docker / containerd / Podman on-disk state.**

Reconstructs container activity from `/var/lib/docker` (and containerd / Podman
equivalents): image and layer inventory, per-container `config.v2.json` /
`hostconfig.json`, `*-json.log` stdout/stderr, mounts, and the `overlay2` layer
stack for a given container.

## Planned scope

- Container inventory: name, image, command, created / started / finished, exit
  code
- Mount / bind / volume map; environment and port bindings
- Reassemble container console logs into a timeline
- List / extract files from a container's merged filesystem view

## Inputs

A mounted Linux image with a container runtime's data directory.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`recovery_fs`, `linux_syslog`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
