r"""analysis_antiforensics - correlate evidence-destruction indicators.

Consumes the CSV / JSON output of the other tools (it does not re-parse
artefacts) and produces one findings list: event-log clearing (1102 /
104) and record-sequence gaps, timeline gaps across log sources,
``$LogFile`` / ``$UsnJrnl`` truncation, ``$SI`` vs ``$FN`` timestomping and
zeroed sub-seconds, disabled Prefetch / SRUM / Amcache, Defender being
switched off, known wiping-tool execution, PowerShell history clearing,
and bursts of file deletions.

Each finding carries a severity (``info`` / ``low`` / ``medium`` /
``high``), the supporting evidence rows, and the relevant timestamp(s).
Emits JSON and a self-contained HTML report.
"""

__version__ = "0.1.0"
