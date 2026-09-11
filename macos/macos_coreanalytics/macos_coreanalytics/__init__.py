r"""macos_coreanalytics - CoreAnalytics (.core_analytics) app-usage aggregates.

Reads the daily analytics bundles macOS writes under
``/Library/Logs/DiagnosticReports/Analytics-*.core_analytics`` (and the
per-user ``~/Library/Logs/DiagnosticReports/`` copies): a compact record
of what ran, how long, and how often, spanning weeks.

Each file is either a binary/XML property list (read with the standard
library's ``plistlib`` - unwrapping an ``NSKeyedArchiver`` payload if
present) or, on builds that write the aggregate as newline-delimited
JSON, one JSON object per line.  The internal record shape is not
publicly documented and has drifted across macOS versions, so extraction
is **schema-tolerant**: every record is walked for a name-like field, a
timestamp, and a message/counters dict, and known counter aliases
(launches, foreground / active seconds) are pulled out when present;
anything else is preserved as JSON in an ``extra`` column.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
