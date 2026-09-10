r"""windows_spooler - print-spool artefact forensics.

Parses the ``.shd`` job-header and ``.spl`` spool-data files left in
``C:\Windows\System32\spool\PRINTERS`` (live, or carved from an image).
Recovers the job owner, source machine, document name, printer, driver and
submit time from the ``.shd``, and identifies / measures the ``.spl``
payload (EMF, XPS / OpenXPS, PostScript, PCL, raw).

A spool file that is still on disk is a print job that did not complete
cleanly - and it contains the document that was printed.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
