from windows_pslogging.evtx.headers import (
    ChunkHeader,
    EvtxError,
    FileHeader,
    iter_chunks,
    iter_records,
)
from windows_pslogging.evtx.record import EventRecord, parse_record


def parse_evtx(data: bytes):
    """Yield an :class:`EventRecord` for every event in an EVTX byte string."""
    FileHeader.parse(data)          # validate signature / raise EvtxError
    from windows_pslogging.evtx.headers import FILE_HEADER_SIZE

    for number, chunk in iter_chunks(data):
        base = FILE_HEADER_SIZE + number * len(chunk)
        for raw in iter_records(number, chunk, base):
            yield parse_record(raw, chunk)


__all__ = [
    "FileHeader", "ChunkHeader", "EvtxError", "EventRecord",
    "iter_chunks", "iter_records", "parse_record", "parse_evtx",
]
