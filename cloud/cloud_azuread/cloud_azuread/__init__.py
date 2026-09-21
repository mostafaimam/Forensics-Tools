"""cloud_azuread - normalise Entra ID (Azure AD) sign-in and directory
audit log JSON exports (portal export, Microsoft Graph API, or Log
Analytics) into one row per event.

Both log types are Microsoft's own long-stable, publicly documented
schemas (the Graph API ``signIns`` and ``directoryAudits`` resources) -
no undocumented-structure caveat here. Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
