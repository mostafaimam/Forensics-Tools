"""cloud_m365ual - normalise the Microsoft 365 Unified Audit Log.

Reads UAL exports from the Purview portal (CSV or JSON) or
``Search-UnifiedAuditLog`` (JSON), where each record's real detail lives
in an ``AuditData`` field - a JSON *string* that needs a second parse -
and flattens the disparate per-workload schemas (Exchange, SharePoint /
OneDrive, Entra ID, Teams) into one common activity row. This is
Microsoft's own long-stable, publicly documented log format - no
undocumented-structure caveat here. Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
