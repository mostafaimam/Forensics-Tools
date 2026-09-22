r"""memory_consoles - best-effort console-host process discovery and
command-line string carving from a Windows memory image.

**Confidence & Validation - read before relying on this.** Console
screen/history buffers are `conhost.exe`/`csrss.exe` **user-mode**
constructs (`CONSOLE_INFORMATION` and its history-buffer chain), not
kernel objects - unlike every other pool-tag-scan tool in this suite.
Their internal layout is documented nowhere publicly; the closest
public prior art (Volatility's `consoles`/`cmdscan` plugins) works from
hand-maintained, per-Windows-build offset tables this project does not
have reliably memorized, and fabricating one would risk confidently
-wrong output - the same false-precision this project avoids
throughout.

Given that, v0.1 does not attempt `CONSOLE_INFORMATION` structure
decoding at all. Instead it reports two separate, honestly-bounded
signals: **which processes matching known console-host/shell image
names** (`conhost.exe`, `cmd.exe`, `powershell.exe`, `pwsh.exe`) were
present, found by the same `_EPROCESS`/`ImageFileName` pool-tag
technique the rest of this suite's process-listing tools use; and
**generic printable-string carving** across the whole image, filtered
to a light "looks command-line-shaped" heuristic (starts with a word
character, contains a space, plausible length). **These two signals
are not correlated with each other** - a carved string is not claimed
to belong to any specific process's console buffer, since verifying
that would need the same undocumented structure layout this tool
avoids guessing at. Treat carved strings as leads to review, not
confirmed command-history entries.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
