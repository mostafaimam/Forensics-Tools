"""analysis_email - inventory email: MBOX / EML / Outlook MSG.

One normalised row per message: headers, addresses, send/delivery times,
attachments (name + size + SHA-256), the Received chain, and heuristic flags
for spoofing (From vs Return-Path, Reply-To mismatch) and SPF/DKIM/DMARC
failures.  PST / OST: export to MBOX / EML first.
"""

__version__ = "0.1.0"
