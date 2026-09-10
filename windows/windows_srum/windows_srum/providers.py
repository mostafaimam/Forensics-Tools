"""SRUM provider-table GUIDs and their column maps."""

from __future__ import annotations

# GUID (as stored, upper-case with braces) -> (short name, column map)
# column map: normalised field -> source column name in the ESE table
PROVIDERS = {
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": ("network-data", {
        "interface_luid": "InterfaceLuid",
        "profile": "L2ProfileId",
        "bytes_sent": "BytesSent",
        "bytes_recvd": "BytesRecvd",
    }),
    "{DD6636C4-8929-4683-974E-22C046A43763}": ("network-connectivity", {
        "interface_luid": "InterfaceLuid",
        "connected_seconds": "ConnectedTime",
        "connect_start": "ConnectStartTime",
    }),
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": ("application-resource", {
        "fg_cycle_time": "ForegroundCycleTime",
        "bg_cycle_time": "BackgroundCycleTime",
        "face_time": "FaceTime",
        "fg_bytes_read": "ForegroundBytesRead",
        "fg_bytes_written": "ForegroundBytesWritten",
        "bg_bytes_read": "BackgroundBytesRead",
        "bg_bytes_written": "BackgroundBytesWritten",
    }),
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": ("energy-usage", {
        "charge_level": "ChargeLevel",
        "cycle_count": "CycleCount",
        "configuration_hash": "ConfigurationHash",
    }),
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": ("energy-usage-lt", {
        "charge_level": "ChargeLevel",
        "cycle_count": "CycleCount",
    }),
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": ("push-notification", {
        "payload_size": "PayloadSize",
        "network_type": "NetworkType",
        "notification_type": "NotificationType",
    }),
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": ("app-timeline", {
        "duration_ms": "DurationMS",
        "end_time": "EndTime",
        "flags": "Flags",
    }),
}

# common columns present on every provider table
COMMON = {"row_id": "AutoIncId", "timestamp": "TimeStamp",
          "app_id": "AppId", "user_id": "UserId"}

ID_MAP_TABLE = "SruDbIdMapTable"
CHECKPOINT_TABLE = "SruDbCheckpointTable"
