# linux_bashhist

**Shell and REPL history recovery across every user.** Finds all history
files on a system, parses the per-shell timestamp formats, merges them into
one ordered timeline, and flags commands that look like attacker activity.

Handles:

| Shell / REPL | Files | Timestamps |
|---|---|---|
| bash / sh / ash | `.bash_history`, `.sh_history`, `.history` | `#<epoch>` lines (`HISTTIMEFORMAT`) |
| zsh | `.zsh_history`, `.zhistory` | `: <epoch>:<elapsed>;cmd` extended format |
| fish | `.local/share/fish/fish_history` | `when:` field |
| python / node / psql / sqlite / redis / irb | `.python_history`, … | none |
| mysql | `.mysql_history` | none (`\040` unescaped) |

```
linux_bashhist /                       # the live host
linux_bashhist /mnt/image --csv hist.csv
linux_bashhist /mnt/image --notable-only
linux_bashhist --file /home/bob/.bash_history --user bob
```

Zero third-party dependencies, cross-platform — read a Linux image's history
from Windows or macOS.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/linux/linux_bashhist
pip install -e .
```

---

## Usage

Point it at a filesystem root (`/` or a mount) and it walks `root/` and
`home/*` for every user's history files. Or pass individual files with
`--file` (repeatable) and label the owner with `--user`.

```bash
# everything, oldest first (undated entries sort first, in file order)
linux_bashhist /mnt/evidence --csv history.csv

# just the commands that tripped a heuristic
linux_bashhist /mnt/evidence --notable-only

# one user, download commands only
linux_bashhist /mnt/evidence --user root --grep 'wget|curl|scp'

# include the tampering-marker rows (empty file, out-of-order timestamps)
linux_bashhist /mnt/evidence --with-notes
```

| Switch | |
|---|---|
| `root` | filesystem root to scan |
| `--file PATH` | parse a single history file (repeatable) |
| `--user NAME` | owner label for `--file`; user filter for a scan |
| `--shell bash,zsh,…` | keep only these shells |
| `--grep REGEX` | keep only commands matching (case-insensitive) |
| `--notable-only` | only commands with a heuristic flag |
| `--with-notes` | also emit tampering-marker rows |
| `--from` / `--to` | inclusive time bounds (drops undated entries) |
| `--csv` / `--json` | output files (CSV is UTF-8-BOM, formula-injection safe) |
| `-q` | no table on stdout |

### Columns

`timestamp_utc`, `user`, `shell`, `command` (newlines shown as `\n`),
`notable` (`;`-joined reasons), `note` (per-entry tampering marker),
`source_file`, `line`.

---

## How it works

**bash.** If the file contains any `#<digits>` timestamp lines, entries are the
blocks between them (so a multi-line command stays one entry). If it has none,
every non-blank line is its own entry, undated — matching how bash actually
writes the file.

**zsh.** The extended `: <begin>:<elapsed>;<command>` format is decoded;
commands continued with a trailing `\` are re-joined.

**fish.** The `- cmd:` / `when:` YAML-ish records are read and unescaped.

**Tampering markers.** A `.bash_history` / `.zsh_history` that exists but is
empty, and files whose timestamps go backwards, get a marker row (shown with
`--with-notes`); the individual out-of-order entry also carries a `note`.

**Heuristics** are conservative substring / regex matches over the command —
download-and-pipe-to-shell, `/dev/tcp` shells, base64 / openssl payload
decode, history and log tampering, `chattr +i`, setuid creation, `passwd` /
`shadow` / `sudoers` edits, `authorized_keys` additions, recon commands,
offensive tooling and cryptominer keywords, persistence installs, exfil
patterns, killing a security agent. Every hit is named in `notable`; it points
you at lines to read, it is not a verdict.

---

## Design choices

- **UTC only** where a timestamp exists; undated entries keep an empty
  `timestamp_utc` and sort first.
- **Read-only.**
- **Never crash.** An unreadable file is skipped; a weird line becomes a
  plain entry.
- **Off-host.** Point it at a mounted image from any OS.

---

## Status

bash / zsh / fish / plain formats and the heuristics above are covered by the
test suite (synthetic fixtures — no Linux shell history on the dev box, as
with the other `linux_*` tools). Not yet done: `.viminfo` command history,
`atuin` / `mcfly` SQLite history databases, and correlating commands with
`linux_utmp` sessions / `linux_syslog` sudo events. See the
[backlog](../../BACKLOG.md).
