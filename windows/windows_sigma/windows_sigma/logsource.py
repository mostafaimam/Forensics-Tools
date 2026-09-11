"""Best-effort mapping from a Sigma logsource to the suite's row shapes."""

from __future__ import annotations

_SERVICE_CHANNEL = {
    "security": "security", "system": "system", "application": "application",
    "sysmon": "sysmon",
}


def row_kind(row: dict) -> str:
    """Classify a normalised row by which tool most likely produced it."""
    if "ScriptBlockId" in row or "scriptblock_id" in row or (
            "kind" in row and "notable" in row and "text" in row):
        return "powershell"
    if "EventId" in row or "EventID" in row or "Channel" in row:
        return "evtx"
    return "generic"


def applies(rule_logsource: dict, row: dict) -> bool:
    """True if the rule's logsource is compatible with this row (or the
    rule declared nothing specific, in which case it is tried anyway)."""
    service = str(rule_logsource.get("service", "")).lower()
    product = str(rule_logsource.get("product", "")).lower()
    category = str(rule_logsource.get("category", "")).lower()
    kind = row_kind(row)

    if not service and not category:
        return True  # nothing specific declared - try it everywhere

    if service == "powershell":
        return kind == "powershell" or "PowerShell" in str(
            row.get("Channel", ""))
    if service in _SERVICE_CHANNEL:
        chan = str(row.get("Channel", "")).lower()
        return _SERVICE_CHANNEL[service] in chan
    if service:
        chan = str(row.get("Channel", "")).lower()
        return service in chan
    if product == "windows" and kind in ("evtx", "powershell"):
        return True
    return kind != "generic" or not category
