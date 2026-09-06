"""Apply transaction-log entries to a primary hive image."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_reglog.logfile import (
    BASE_BLOCK_SIZE,
    BaseBlock,
    LogEntry,
    RegLogError,
    parse_log,
)


@dataclass
class ReplayResult:
    recovered: bytes
    applied_sequences: list[int] = field(default_factory=list)
    pages_written: int = 0
    bytes_written: int = 0
    started_dirty: bool = False
    hash_failures: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.applied_sequences)


def _base_checksum(block: bytes) -> int:
    checksum = 0
    for i in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", block, i)[0]
    if checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    elif checksum == 0:
        checksum = 1
    return checksum


def replay(primary: bytes, logs: list[bytes], *, verify: bool = True) -> ReplayResult:
    base = BaseBlock.parse(primary)
    if base.is_log:
        raise RegLogError("the primary file is itself a transaction log")

    result = ReplayResult(recovered=primary)
    result.started_dirty = base.is_dirty

    # collect every log entry from every supplied log, newest-wins on ties
    all_entries: dict[int, LogEntry] = {}
    for raw in logs:
        try:
            _lb, entries = parse_log(raw)
        except RegLogError as e:
            result.notes.append(f"skipped a log: {e}")
            continue
        for e in entries:
            all_entries.setdefault(e.sequence, e)

    if not all_entries:
        result.notes.append("no usable log entries found")
        return result

    image = bytearray(primary)
    current = base.secondary_sequence
    seq = current
    hbins_size = base.hive_bins_size

    # apply contiguously from secondary_sequence upward
    while True:
        nxt = all_entries.get(seq)
        if nxt is None:
            nxt = all_entries.get(seq + 1)
            if nxt is None:
                break
            seq += 1
        if verify and not nxt.hash1_ok:
            result.hash_failures += 1
            result.notes.append(
                f"entry seq {nxt.sequence}: hash-1 mismatch (applied anyway)")

        for page in nxt.pages:
            start = BASE_BLOCK_SIZE + page.offset
            end = start + page.size
            if end > len(image):
                image.extend(b"\x00" * (end - len(image)))
            image[start:end] = page.data.ljust(page.size, b"\x00")[:page.size]
            result.pages_written += 1
            result.bytes_written += page.size

        hbins_size = nxt.hive_bins_size
        result.applied_sequences.append(nxt.sequence)
        seq = nxt.sequence + 1

    if not result.applied_sequences:
        return result

    last_seq = result.applied_sequences[-1] + 1
    struct.pack_into("<II", image, 4, last_seq, last_seq)
    struct.pack_into("<I", image, 0x28, hbins_size)
    struct.pack_into("<I", image, 0x1FC, _base_checksum(bytes(image[:508])))

    # trim to base block + hive bins
    total = BASE_BLOCK_SIZE + hbins_size
    if total <= len(image):
        image = image[:total]

    result.recovered = bytes(image)
    return result


def replay_files(primary_path, log_paths, *, verify: bool = True) -> ReplayResult:
    from pathlib import Path

    primary = Path(primary_path).read_bytes()
    logs = [Path(p).read_bytes() for p in log_paths]
    return replay(primary, logs, verify=verify)
