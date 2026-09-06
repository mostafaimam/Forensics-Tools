r"""Parse a Windows Shell Link (``.lnk``) - [MS-SHLLINK].

Layout::

    ShellLinkHeader        76 bytes
    LinkTargetIDList       if HasLinkTargetIDList  (u16 size + ItemID list)
    LinkInfo              if HasLinkInfo
    StringData            Name, RelativePath, WorkingDir, Arguments, IconLocation
    ExtraData            a sequence of typed blocks, ended by a size < 4
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from windows_lnk.shellitems import parse_idlist

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
HEADER_SIZE = 0x4C
LINK_CLSID = uuid.UUID("00021401-0000-0000-c000-000000000046")

# LinkFlags
F_HAS_TARGET_IDLIST = 0x00000001
F_HAS_LINK_INFO = 0x00000002
F_HAS_NAME = 0x00000004
F_HAS_RELATIVE_PATH = 0x00000008
F_HAS_WORKING_DIR = 0x00000010
F_HAS_ARGUMENTS = 0x00000020
F_HAS_ICON_LOCATION = 0x00000040
F_IS_UNICODE = 0x00000080

_SHOW = {1: "Normal", 3: "Maximized", 7: "MinimizedNoActivate"}
_DRIVE_TYPE = {0: "Unknown", 1: "NoRootDir", 2: "Removable", 3: "Fixed",
               4: "Remote", 5: "CD-ROM", 6: "RAM disk"}

_FILE_ATTRS = {
    0x0001: "READONLY", 0x0002: "HIDDEN", 0x0004: "SYSTEM",
    0x0010: "DIRECTORY", 0x0020: "ARCHIVE", 0x0040: "DEVICE",
    0x0080: "NORMAL", 0x0100: "TEMPORARY", 0x0200: "SPARSE",
    0x0400: "REPARSE_POINT", 0x0800: "COMPRESSED", 0x1000: "OFFLINE",
    0x2000: "NOT_CONTENT_INDEXED", 0x4000: "ENCRYPTED",
}


class LnkError(ValueError):
    pass


def _ft(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if isinstance(dt, datetime) else ""


@dataclass
class TrackerInfo:
    machine_id: str = ""
    droid_volume: str = ""
    droid_object: str = ""
    droid_birth_volume: str = ""
    droid_birth_object: str = ""
    object_created_utc: datetime | None = None
    object_mac_address: str = ""


@dataclass
class Lnk:
    source: str = ""
    flags: int = 0
    flag_names: list = field(default_factory=list)
    file_attributes: list = field(default_factory=list)
    target_created: datetime | None = None
    target_accessed: datetime | None = None
    target_modified: datetime | None = None
    target_size: int = 0
    icon_index: int = 0
    show_command: str = ""
    hotkey: int = 0

    name: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""

    drive_type: str = ""
    drive_serial: str = ""
    volume_label: str = ""
    local_base_path: str = ""
    network_share: str = ""
    common_path_suffix: str = ""

    tracker: TrackerInfo | None = None
    known_folder: str = ""
    environment_target: str = ""
    target_items: list = field(default_factory=list)
    extra_blocks: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def target_path(self) -> str:
        if self.local_base_path:
            return self.local_base_path + self.common_path_suffix
        if self.network_share:
            return self.network_share + "\\" + self.common_path_suffix
        if self.environment_target:
            return self.environment_target
        if self.target_items:
            return "\\".join(i.get("long_name") or i.get("name", "")
                             for i in self.target_items
                             if i.get("long_name") or i.get("name"))
        return ""


def parse(data: bytes, source: str = "<bytes>") -> Lnk:
    if len(data) < HEADER_SIZE:
        raise LnkError(f"too small ({len(data)} bytes)")
    if struct.unpack_from("<I", data, 0)[0] != HEADER_SIZE:
        raise LnkError("bad header size")
    if uuid.UUID(bytes_le=data[4:20]) != LINK_CLSID:
        raise LnkError("not a Shell Link (wrong CLSID)")

    lnk = Lnk(source=source)
    lnk.flags = struct.unpack_from("<I", data, 20)[0]
    lnk.flag_names = _flag_names(lnk.flags)
    attrs = struct.unpack_from("<I", data, 24)[0]
    lnk.file_attributes = [v for k, v in _FILE_ATTRS.items() if attrs & k]
    c, a, w = struct.unpack_from("<QQQ", data, 28)
    lnk.target_created, lnk.target_accessed, lnk.target_modified = \
        _ft(c), _ft(a), _ft(w)
    lnk.target_size = struct.unpack_from("<I", data, 52)[0]
    lnk.icon_index = struct.unpack_from("<i", data, 56)[0]
    lnk.show_command = _SHOW.get(struct.unpack_from("<I", data, 60)[0], "Normal")
    lnk.hotkey = struct.unpack_from("<H", data, 64)[0]

    pos = HEADER_SIZE
    unicode = bool(lnk.flags & F_IS_UNICODE)

    if lnk.flags & F_HAS_TARGET_IDLIST:
        size = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        try:
            lnk.target_items = parse_idlist(data[pos:pos + size])
        except Exception as e:  # noqa: BLE001
            lnk.warnings.append(f"target id list: {e}")
        pos += size

    if lnk.flags & F_HAS_LINK_INFO:
        try:
            pos = _parse_link_info(lnk, data, pos)
        except Exception as e:  # noqa: BLE001
            lnk.warnings.append(f"link info: {e}")

    for flag, attr in ((F_HAS_NAME, "name"),
                       (F_HAS_RELATIVE_PATH, "relative_path"),
                       (F_HAS_WORKING_DIR, "working_dir"),
                       (F_HAS_ARGUMENTS, "arguments"),
                       (F_HAS_ICON_LOCATION, "icon_location")):
        if lnk.flags & flag and pos + 2 <= len(data):
            n = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            width = 2 if unicode else 1
            raw = data[pos:pos + n * width]
            setattr(lnk, attr,
                    raw.decode("utf-16-le", "replace") if unicode else _ansi(raw))
            pos += n * width

    _parse_extra(lnk, data, pos)
    return lnk


def _flag_names(flags: int) -> list:
    names = []
    for bit, name in (
        (0x1, "HasLinkTargetIDList"), (0x2, "HasLinkInfo"), (0x4, "HasName"),
        (0x8, "HasRelativePath"), (0x10, "HasWorkingDir"), (0x20, "HasArguments"),
        (0x40, "HasIconLocation"), (0x80, "IsUnicode"),
        (0x100, "ForceNoLinkInfo"), (0x200, "HasExpString"),
        (0x400, "RunInSeparateProcess"), (0x2000, "HasDarwinID"),
        (0x4000, "RunAsUser"), (0x8000, "HasExpIcon"),
        (0x40000, "RunWithShimLayer"), (0x400000, "PreferEnvironmentPath"),
    ):
        if flags & bit:
            names.append(name)
    return names


def _ansi(raw: bytes) -> str:
    for enc in ("mbcs", "cp1252", "latin-1"):
        try:
            return raw.decode(enc, "replace")
        except LookupError:
            continue
    return raw.decode("latin-1", "replace")


def _cstr(data: bytes, off: int, unicode: bool = False) -> str:
    if unicode:
        end = data.find(b"\x00\x00", off)
        if end < 0:
            end = len(data)
        elif (end - off) % 2:
            end += 1
        return data[off:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", off)
    end = len(data) if end < 0 else end
    return _ansi(data[off:end])


def _parse_link_info(lnk: Lnk, data: bytes, pos: int) -> int:
    base = pos
    info_size = struct.unpack_from("<I", data, pos)[0]
    header_size = struct.unpack_from("<I", data, pos + 4)[0]
    info_flags = struct.unpack_from("<I", data, pos + 8)[0]
    vol_off = struct.unpack_from("<I", data, pos + 12)[0]
    lbp_off = struct.unpack_from("<I", data, pos + 16)[0]
    cnrl_off = struct.unpack_from("<I", data, pos + 20)[0]
    cps_off = struct.unpack_from("<I", data, pos + 24)[0]
    lbp_off_u = cps_off_u = 0
    if header_size >= 0x24:
        lbp_off_u = struct.unpack_from("<I", data, pos + 28)[0]
        cps_off_u = struct.unpack_from("<I", data, pos + 32)[0]

    if info_flags & 0x1 and vol_off:
        v = base + vol_off
        drive_type = struct.unpack_from("<I", data, v + 4)[0]
        serial = struct.unpack_from("<I", data, v + 8)[0]
        label_off = struct.unpack_from("<I", data, v + 12)[0]
        lnk.drive_type = _DRIVE_TYPE.get(drive_type, str(drive_type))
        lnk.drive_serial = f"{serial:08X}"
        if label_off:
            lnk.volume_label = _cstr(data, v + label_off)
        if lbp_off_u:
            lnk.local_base_path = _cstr(data, base + lbp_off_u, unicode=True)
        elif lbp_off:
            lnk.local_base_path = _cstr(data, base + lbp_off)

    if info_flags & 0x2 and cnrl_off:
        n = base + cnrl_off
        net_name_off = struct.unpack_from("<I", data, n + 8)[0]
        if net_name_off:
            lnk.network_share = _cstr(data, n + net_name_off)

    if cps_off_u:
        lnk.common_path_suffix = _cstr(data, base + cps_off_u, unicode=True)
    elif cps_off:
        lnk.common_path_suffix = _cstr(data, base + cps_off)

    return base + info_size


_KNOWN_FOLDERS = {
    "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": "RoamingAppData",
    "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": "LocalAppData",
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
    "FDD39AD0-238F-46AF-ADB4-6C85480369C7": "Documents",
    "374DE290-123F-4565-9164-39C4925E467B": "Downloads",
    "33E28130-4E1E-4676-835A-98395C3BC3BB": "Pictures",
    "1777F761-68AD-4D8A-87BD-30B759FA33DD": "Favorites",
    "4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4": "SavedGames",
    "18989B1D-99B5-455B-841C-AB7C74E4DDFC": "Videos",
    "A63293E8-664E-48DB-A079-DF759E0509F7": "Templates",
}


def _parse_extra(lnk: Lnk, data: bytes, pos: int) -> None:
    n = len(data)
    while pos + 8 <= n:
        size = struct.unpack_from("<I", data, pos)[0]
        if size < 4 or pos + size > n:
            break
        sig = struct.unpack_from("<I", data, pos + 4)[0]
        block = data[pos:pos + size]
        lnk.extra_blocks.append(f"{sig:#010x}")
        if sig == 0xA0000003:                     # TrackerDataBlock
            _parse_tracker(lnk, block)
        elif sig == 0xA000000B and size >= 0x1C:   # KnownFolderDataBlock
            g = str(uuid.UUID(bytes_le=block[12:28])).upper()
            lnk.known_folder = _KNOWN_FOLDERS.get(g, g)
        elif sig in (0xA0000001, 0xA0000007) and size >= 0x88:
            # EnvironmentVariableDataBlock / IconEnvironmentDataBlock
            ansi = _ansi(block[12:12 + 260].split(b"\x00")[0])
            uni = block[12 + 260:12 + 260 + 520].split(b"\x00\x00")[0].decode(
                "utf-16-le", "replace")
            if sig == 0xA0000001:
                lnk.environment_target = uni or ansi
        pos += size


def _parse_tracker(lnk: Lnk, block: bytes) -> None:
    if len(block) < 0x60:
        return
    t = TrackerInfo()
    t.machine_id = _ansi(block[16:16 + 16].split(b"\x00")[0])
    try:
        t.droid_volume = str(uuid.UUID(bytes_le=block[32:48])).upper()
        obj = uuid.UUID(bytes_le=block[48:64])
        t.droid_object = str(obj).upper()
        t.droid_birth_volume = str(uuid.UUID(bytes_le=block[64:80])).upper()
        t.droid_birth_object = str(uuid.UUID(bytes_le=block[80:96])).upper()
        birth = uuid.UUID(bytes_le=block[48:64])
        if birth.version == 1:
            t.object_created_utc = _uuid1_time(birth)
            t.object_mac_address = _uuid1_mac(birth)
    except (ValueError, IndexError):
        pass
    lnk.tracker = t


_GREGORIAN_EPOCH = datetime(1582, 10, 15, tzinfo=timezone.utc)


def _uuid1_time(u: uuid.UUID) -> datetime | None:
    # UUID v1 .time is 100-ns intervals since 1582-10-15
    try:
        return _GREGORIAN_EPOCH + timedelta(microseconds=u.time / 10)
    except (ValueError, OverflowError):
        return None


def _uuid1_mac(u: uuid.UUID) -> str:
    node = u.node
    return ":".join(f"{(node >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))
