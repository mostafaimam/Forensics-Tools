r"""Parse a BitLocker FVE metadata block into protectors + the wrapped FVEK.

.. note::
   The exact on-disk metadata TLV layout is undocumented by Microsoft and
   has been reverse-engineered by open-source projects over many years;
   this parser follows that general *shape* (a header, then a sequence of
   type/length/value entries, VMK protectors nesting a stretch-key salt
   and an AES-CCM-wrapped key, a separate AES-CCM-wrapped FVEK dataset)
   but has not been byte-verified against a real Windows-written volume
   in this environment - see the package README.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_SIGNATURE = b"-FVE-FS-"
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

ENTRY_VMK = 0x0002
ENTRY_FVEK = 0x0003
VALUE_COMPOSITE = 0x0000
VALUE_STRETCH_KEY = 0x0003
VALUE_AES_CCM_KEY = 0x0005

PROTECTOR_TYPES = {0x0000: "clear key", 0x0001: "TPM", 0x0002:
                  "recovery password", 0x0003: "external key (.BEK)",
                  0x0004: "TPM + PIN", 0x0005: "password"}
METHODS = {0x1000: ("aes-128-cbc", 16), 0x1001: ("aes-256-cbc", 32),
          0x2000: ("aes-128-xts", 16), 0x2001: ("aes-256-xts", 32)}


def _filetime(v: int) -> str:
    if not v or v > 0x7FFF_FFFF_FFFF_FFFF:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


class FveError(ValueError):
    pass


@dataclass
class Protector:
    guid: str
    last_modified: str
    protector_type: str
    salt: bytes = b""
    nonce: bytes = b""
    wrapped_key: bytes = b""


@dataclass
class FveMetadata:
    volume_guid: str
    method: str
    creation_time: str
    protectors: list = field(default_factory=list)
    fvek_nonce: bytes = b""
    fvek_wrapped: bytes = b""


def _entries(buf: bytes, off: int, end: int):
    while off + 8 <= end:
        total, etype, vtype, _ver = struct.unpack_from("<HHHH", buf, off)
        if total < 8 or off + total > end:
            break
        yield etype, vtype, buf[off + 8:off + total]
        off += total


def parse(data: bytes) -> FveMetadata:
    if len(data) < 0x30 or data[:8] != _SIGNATURE:
        raise FveError("not a recognised FVE metadata block "
                       "(missing -FVE-FS- signature)")
    guid = str(uuid.UUID(bytes_le=data[0x0C:0x1C]))
    method_code = struct.unpack_from("<I", data, 0x20)[0]
    method = METHODS.get(method_code, (f"unknown({method_code:#x})", 32))[0]
    created = _filetime(struct.unpack_from("<Q", data, 0x24)[0])
    meta_size = struct.unpack_from("<I", data, 0x2C)[0]
    end = min(len(data), 0x30 + meta_size) if meta_size else len(data)

    fve = FveMetadata(volume_guid=guid, method=method, creation_time=created)
    for etype, vtype, value in _entries(data, 0x30, end):
        if etype == ENTRY_VMK and vtype == VALUE_COMPOSITE:
            if len(value) < 28:
                continue
            pguid = str(uuid.UUID(bytes_le=value[0:16]))
            lastmod = _filetime(struct.unpack_from("<Q", value, 16)[0])
            ptype = struct.unpack_from("<H", value, 24)[0]
            prot = Protector(guid=pguid, last_modified=lastmod,
                             protector_type=PROTECTOR_TYPES.get(
                                 ptype, f"unknown({ptype:#x})"))
            for e2, v2, val2 in _entries(value, 28, len(value)):
                if v2 == VALUE_STRETCH_KEY and len(val2) >= 16:
                    prot.salt = val2[:16]
                elif v2 == VALUE_AES_CCM_KEY and len(val2) >= 12:
                    prot.nonce = val2[:12]
                    prot.wrapped_key = val2[12:]
            fve.protectors.append(prot)
        elif etype == ENTRY_FVEK and vtype == VALUE_AES_CCM_KEY:
            if len(value) >= 12:
                fve.fvek_nonce = value[:12]
                fve.fvek_wrapped = value[12:]
    return fve
