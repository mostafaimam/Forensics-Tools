r"""windows_wer - Windows Error Reporting forensics.

Parses ``.wer`` report files (and the ``ReportArchive`` / ``ReportQueue``
stores) into one row per crash / hang: the faulting application and its
full path, version, the faulting module, the exception code and offset, the
event time, and the problem signature.  A ``.wer`` report is durable
evidence that a program **ran** - and often survives long after the
executable itself is gone.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
