"""Low-level $LogFile page + log-record parser."""

from __future__ import annotations

import struct
from dataclasses import dataclass

PAGE = 4096

OPS = {
    0x00: "Noop", 0x01: "CompensationLogRecord",
    0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment",
    0x04: "WriteEndOfFileRecordSegment", 0x05: "CreateAttribute",
    0x06: "DeleteAttribute", 0x07: "UpdateResidentValue",
    0x08: "UpdateNonResidentValue", 0x09: "UpdateMappingPairs",
    0x0A: "DeleteDirtyClusters", 0x0B: "SetNewAttributeSizes",
    0x0C: "AddIndexEntryRoot", 0x0D: "DeleteIndexEntryRoot",
    0x0E: "AddIndexEntryAllocation", 0x0F: "DeleteIndexEntryAllocation",
    0x10: "WriteEndOfIndexBuffer", 0x11: "SetIndexEntryVcnRoot",
    0x12: "SetIndexEntryVcnAllocation", 0x13: "UpdateFileNameRoot",
    0x14: "UpdateFileNameAllocation", 0x15: "SetBitsInNonResidentBitMap",
    0x16: "ClearBitsInNonResidentBitMap", 0x17: "HotFix",
    0x18: "EndTopLevelAction", 0x19: "PrepareTransaction",
    0x1A: "CommitTransaction", 0x1B: "ForgetTransaction",
    0x1C: "OpenNonResidentAttribute", 0x1D: "OpenAttributeTableDump",
    0x1E: "AttributeNamesDump", 0x1F: "DirtyPageTableDump",
    0x20: "TransactionTableDump", 0x21: "UpdateRecordDataRoot",
    0x22: "UpdateRecordDataAllocation",
}


class LogError(Exception):
    pass


@dataclass
class LogRecord:
    lsn: int
    prev_lsn: int
    undo_next_lsn: int
    transaction_id: int
    record_type: int
    redo_op: int
    undo_op: int
    redo: bytes
    undo: bytes
    target_attribute: int
    mft_cluster_index: int
    target_vcn: int
    target_lcn: int
    page: int
    offset: int

    @property
    def redo_name(self) -> str:
        return OPS.get(self.redo_op, f"op_{self.redo_op:#x}")

    @property
    def undo_name(self) -> str:
        return OPS.get(self.undo_op, f"op_{self.undo_op:#x}")


def _apply_usa(page: bytes) -> bytes:
    if len(page) < 8:
        return page
    usa_off, usa_cnt = struct.unpack_from("<HH", page, 4)
    if usa_off == 0 or usa_cnt == 0 or usa_off + usa_cnt * 2 > len(page):
        return page
    b = bytearray(page)
    seq = page[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        pos = i * 512 - 2
        if pos + 2 > len(b):
            break
        fix = page[usa_off + i * 2:usa_off + i * 2 + 2]
        if page[pos:pos + 2] != seq:
            # stale / unfixable page - leave as-is but note by returning
            pass
        b[pos:pos + 2] = fix
    return bytes(b)


def _iter_pages(data: bytes):
    for pnum, base in enumerate(range(0, len(data), PAGE)):
        page = data[base:base + PAGE]
        if len(page) < 8:
            continue
        magic = page[:4]
        if magic in (b"RCRD", b"RSTR", b"CHKD"):
            yield pnum, magic, _apply_usa(page)


_RCRD_HDR = 0x40      # first log record offset within an RCRD page


def _parse_records_in_page(page: bytes, pnum: int):
    pos = _RCRD_HDR
    guard = 0
    while pos + 0x30 <= PAGE and guard < 512:
        guard += 1
        this_lsn, prev_lsn, undo_next = struct.unpack_from("<QQQ", page, pos)
        client_data_len = struct.unpack_from("<I", page, pos + 0x18)[0]
        record_type, tx_id = struct.unpack_from("<II", page, pos + 0x20)
        if this_lsn == 0 or client_data_len < 0x28 or \
                client_data_len > PAGE - 0x30 or record_type not in (1, 2):
            break
        cd = page[pos + 0x30: pos + 0x30 + client_data_len]
        if record_type == 1 and len(cd) >= 0x28:
            (redo_op, undo_op, redo_off, redo_len, undo_off, undo_len,
             target_attr, _lcns, _rec_off, _attr_off,
             mft_ci) = struct.unpack_from("<HHHHHHHHHHH", cd, 0)
            target_vcn = struct.unpack_from("<I", cd, 0x18)[0] \
                if len(cd) >= 0x1C else 0
            redo = cd[redo_off: redo_off + redo_len] \
                if 0 <= redo_off <= len(cd) else b""
            undo = cd[undo_off: undo_off + undo_len] \
                if 0 <= undo_off <= len(cd) else b""
            yield LogRecord(
                lsn=this_lsn, prev_lsn=prev_lsn, undo_next_lsn=undo_next,
                transaction_id=tx_id, record_type=record_type,
                redo_op=redo_op, undo_op=undo_op, redo=redo, undo=undo,
                target_attribute=target_attr, mft_cluster_index=mft_ci,
                target_vcn=target_vcn, target_lcn=0, page=pnum, offset=pos)
        pos += 0x30 + ((client_data_len + 7) & ~7)


@dataclass
class LogFile:
    records: list
    rstr_pages: int
    rcrd_pages: int
    errors: list


def parse(data: bytes) -> LogFile:
    records = []
    rstr = rcrd = 0
    errors: list[str] = []
    for pnum, magic, page in _iter_pages(data):
        if magic == b"RSTR":
            rstr += 1
            continue
        rcrd += 1
        try:
            for r in _parse_records_in_page(page, pnum):
                records.append(r)
        except (struct.error, IndexError) as e:
            errors.append(f"page {pnum}: {e}")
    records.sort(key=lambda r: r.lsn)
    return LogFile(records=records, rstr_pages=rstr, rcrd_pages=rcrd,
                   errors=errors)
