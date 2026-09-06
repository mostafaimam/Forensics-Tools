"""analysis_report - bundle tool output into one case report.

Takes the CSV / JSON exports of the other tools (plus free-form notes in
Markdown) and produces a single self-contained HTML report: case header, a
collapsible table per source, highlighted alert rows (``notable`` / ``flags``
/ ``verdict`` / ``status`` columns), a SHA-256 manifest of every input, and a
summary.  A ``--json`` bundle is written alongside.
"""

__version__ = "0.1.0"
