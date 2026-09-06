from __future__ import annotations

import struct
from dataclasses import dataclass

_OEM = b"NTFS    "


class NotNtfsError(ValueError):
    pass


@dataclass
class BootSector:
    bytes_per_sector: int
    sectors_per_cluster: int
    total_sectors: int
    mft_cluster: int
    mftmirr_cluster: int
    bytes_per_mft_record: int
    serial_number: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def mft_offset(self) -> int:
        return self.mft_cluster * self.cluster_size


def parse_boot_sector(data: bytes) -> BootSector:
    if len(data) < 512:
        raise NotNtfsError("boot sector too small")
    if data[3:11] != _OEM:
        raise NotNtfsError(f"not an NTFS volume (OEM id {data[3:11]!r})")

    bps = struct.unpack_from("<H", data, 0x0B)[0]
    spc = data[0x0D]
    total = struct.unpack_from("<Q", data, 0x28)[0]
    mft = struct.unpack_from("<Q", data, 0x30)[0]
    mftmirr = struct.unpack_from("<Q", data, 0x38)[0]
    raw_rec = struct.unpack_from("<b", data, 0x40)[0]
    serial = struct.unpack_from("<Q", data, 0x48)[0]

    if bps == 0 or spc == 0:
        raise NotNtfsError("invalid geometry in boot sector")

    if raw_rec > 0:
        rec_size = raw_rec * bps * spc
    else:
        rec_size = 1 << (-raw_rec)

    return BootSector(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        total_sectors=total,
        mft_cluster=mft,
        mftmirr_cluster=mftmirr,
        bytes_per_mft_record=rec_size,
        serial_number=serial,
    )
