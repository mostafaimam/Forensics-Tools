"""A minimal read-only NBD (Network Block Device) server.

Serves one :class:`~mounting_image.formats.base.Image` (whole disk or a
partition slice).  On Linux:

    sudo modprobe nbd
    sudo nbd-client -N <name> 127.0.0.1 <port> /dev/nbd0
    sudo mount -o ro /dev/nbd0p1 /mnt   # or mount /dev/nbd0 directly

Implements the fixed-newstyle handshake and the READ / DISCONNECT / FLUSH /
WRITE-ZEROES(rejected) transmission commands.  WRITE and TRIM return EPERM.
"""

from __future__ import annotations

import socketserver
import struct
import threading

from mounting_image.formats.base import Image

_NBDMAGIC = b"NBDMAGIC"
_IHAVEOPT = b"IHAVEOPT"
_OPT_REPLY_MAGIC = 0x0003E889045565A9
_REQUEST_MAGIC = 0x25609513
_SIMPLE_REPLY_MAGIC = 0x67446698

NBD_FLAG_FIXED_NEWSTYLE = 1
NBD_FLAG_HAS_FLAGS = 1
NBD_FLAG_READ_ONLY = 2
NBD_FLAG_SEND_FLUSH = 4

NBD_OPT_EXPORT_NAME = 1
NBD_OPT_ABORT = 2
NBD_OPT_LIST = 3
NBD_OPT_INFO = 6
NBD_OPT_GO = 7

NBD_REP_ACK = 1
NBD_REP_SERVER = 2
NBD_REP_INFO = 3
NBD_REP_ERR_UNSUP = 0x80000001

NBD_INFO_EXPORT = 0

NBD_CMD_READ = 0
NBD_CMD_WRITE = 1
NBD_CMD_DISC = 2
NBD_CMD_FLUSH = 3
NBD_CMD_TRIM = 4
NBD_CMD_WRITE_ZEROES = 6

_EPERM = 1
_EINVAL = 22


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        img: Image = self.server.image
        name: str = self.server.export_name
        c = self.request
        c.sendall(_NBDMAGIC + _IHAVEOPT + struct.pack(">H",
                  NBD_FLAG_FIXED_NEWSTYLE))
        _client_flags = _recv(c, 4)
        if not _client_flags:
            return

        transmit = False
        while not transmit:
            hdr = _recv(c, 16)
            if not hdr or hdr[:8] != _IHAVEOPT:
                return
            _magic, opt, length = struct.unpack(">8sII", hdr)
            payload = _recv(c, length) if length else b""
            if opt in (NBD_OPT_EXPORT_NAME,):
                c.sendall(struct.pack(">QH", img.size,
                          NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY
                          | NBD_FLAG_SEND_FLUSH) + b"\x00" * 124)
                transmit = True
            elif opt in (NBD_OPT_INFO, NBD_OPT_GO):
                info = struct.pack(">HQH", NBD_INFO_EXPORT, img.size,
                                   NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY
                                   | NBD_FLAG_SEND_FLUSH)
                _opt_reply(c, opt, NBD_REP_INFO, info)
                _opt_reply(c, opt, NBD_REP_ACK, b"")
                if opt == NBD_OPT_GO:
                    transmit = True
            elif opt == NBD_OPT_LIST:
                entry = struct.pack(">I", len(name)) + name.encode()
                _opt_reply(c, opt, NBD_REP_SERVER, entry)
                _opt_reply(c, opt, NBD_REP_ACK, b"")
            elif opt == NBD_OPT_ABORT:
                _opt_reply(c, opt, NBD_REP_ACK, b"")
                return
            else:
                _opt_reply(c, opt, NBD_REP_ERR_UNSUP, b"")

        self._transmission(c, img)

    def _transmission(self, c, img: Image) -> None:
        while True:
            hdr = _recv(c, 28)
            if not hdr:
                return
            magic, _flags, cmd, handle, offset, length = struct.unpack(
                ">IHHQQI", hdr)
            if magic != _REQUEST_MAGIC:
                return
            if cmd == NBD_CMD_DISC:
                return
            if cmd == NBD_CMD_READ:
                try:
                    data = img.read(offset, length)
                except Exception:  # noqa: BLE001
                    _reply(c, _EINVAL, handle)
                    continue
                _reply(c, 0, handle, data.ljust(length, b"\x00"))
            elif cmd == NBD_CMD_FLUSH:
                _reply(c, 0, handle)
            elif cmd in (NBD_CMD_WRITE, NBD_CMD_WRITE_ZEROES, NBD_CMD_TRIM):
                if cmd == NBD_CMD_WRITE and length:
                    _recv(c, length)
                _reply(c, _EPERM, handle)
            else:
                _reply(c, _EINVAL, handle)


def _opt_reply(c, opt: int, rep: int, payload: bytes) -> None:
    c.sendall(struct.pack(">QII", _OPT_REPLY_MAGIC, opt, rep)
              + struct.pack(">I", len(payload)) + payload)


def _reply(c, error: int, handle: int, data: bytes = b"") -> None:
    c.sendall(struct.pack(">IIQ", _SIMPLE_REPLY_MAGIC, error, handle) + data)


def _recv(c, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


class NBDServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, image: Image, host: str = "127.0.0.1", port: int = 10809,
                 export_name: str = "image"):
        super().__init__((host, port), _Handler)
        self.image = image
        self.export_name = export_name

    def serve_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t
