# analysis_email

**Inventory email.** Parses **MBOX**, **EML** and **Outlook MSG** into one
normalised row per message — headers, addresses, send / delivery times,
attachments (name + size + **SHA-256**), the `Received` chain, and heuristic
flags for spoofing and authentication failures.

```
analysis_email scan /cases/mail --csv messages.csv
analysis_email scan inbox.mbox --attachments-dir ./att
analysis_email scan suspicious.msg --flagged-only --json bec.json
```

> **PST / OST** are detected but not parsed yet — export the folder to MBOX /
> EML first (`readpst`, Thunderbird, Outlook) and re-run.

Zero third-party dependencies (vendors a small OLE2 reader for `.msg`).

---

## Install

```bash
git clone https://github.com/mostafaimam/Forensics-Tools
cd Forensics-Tools/analysis/analysis_email
pip install -e .
```

---

## Usage

`scan` takes files or folders (it sniffs `.eml` / `.msg` / `.mbox` even
without the extension).

| Switch | |
|---|---|
| `--attachments-dir DIR` | also carve every attachment to `DIR/<file>_<index>/<sha12>_<name>` |
| `--with-attachments-only` | only messages that carry an attachment |
| `--flagged-only` | only messages with a spoofing / auth flag |
| `--grep REGEX` | subject / body match |
| `--no-recurse` | don't descend into sub-folders |
| `--csv` / `--json` | output (one row per message) |

`scan` exits **1** if any message is flagged.

### Columns

`date`, `delivered`, `from_name`, `from_addr`, `to`, `cc`, `bcc`, `subject`,
`message_id`, `reply_to`, `return_path`, `x_originating_ip`,
`attachment_count`, `attachments`, `body_bytes`, `has_html`, `flags`.

### Flags

- `From domain != Return-Path domain`
- `Reply-To domain differs from From`
- `SPF / DKIM / DMARC (soft)fail` — from `Authentication-Results`
- `bulk-mailer header present` (PHPMailer &c.)
- `no Received headers`

For MSG the RFC-822 header block (`PidTagTransportMessageHeaders`) is parsed
so the same flags apply; native MSG properties fill in the rest
(`ClientSubmitTime`, `MessageDeliveryTime`, recipients, attachments).

---

## Status

MBOX / EML / MSG parsing, attachment hashing + carving, the Received chain
and the flag heuristics are covered by the test suite (synthetic messages,
including a hand-built OLE2 `.msg` with a mini-FAT). Not yet done: PST / OST
(NDB/LTP), TNEF (`winmail.dat`), S/MIME + PGP/MIME decryption boundaries,
calendar / contact items, and DKIM signature verification. See the project
roadmap.
