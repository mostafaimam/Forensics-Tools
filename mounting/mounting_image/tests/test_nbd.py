import socket
import struct

from _synth import make_mbr_disk
from mounting_image.formats import open_image
from mounting_image.nbd import NBDServer

_NBD_REQUEST_MAGIC = 0x25609513
_NBD_SIMPLE_REPLY_MAGIC = 0x67446698


def _recv(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        assert c, "connection closed early"
        buf += c
    return buf


def test_nbd_export_name_and_read(tmp_path):
    raw = make_mbr_disk()
    p = tmp_path / "d.raw"
    p.write_bytes(raw)
    img = open_image(p)
    srv = NBDServer(img, "127.0.0.1", 0, "img")
    port = srv.server_address[1]
    srv.serve_in_thread()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        assert _recv(s, 8) == b"NBDMAGIC"
        assert _recv(s, 8) == b"IHAVEOPT"
        _recv(s, 2)                                  # handshake flags
        s.sendall(struct.pack(">I", 0))              # client flags

        name = b"img"
        s.sendall(b"IHAVEOPT" + struct.pack(">II", 1, len(name)) + name)
        size = struct.unpack(">Q", _recv(s, 8))[0]
        assert size == len(raw)
        _recv(s, 2 + 124)                            # transmission flags + pad

        # READ 8 bytes at the first partition
        off = 2048 * 512
        s.sendall(struct.pack(">IHHQQI", _NBD_REQUEST_MAGIC, 0, 0, 42, off, 8))
        rep = _recv(s, 16)
        magic, err, handle = struct.unpack(">IIQ", rep)
        assert magic == _NBD_SIMPLE_REPLY_MAGIC and err == 0 and handle == 42
        assert _recv(s, 8) == raw[off:off + 8] == b"PART1\x00\x00\x00"

        # WRITE must be refused (read-only export)
        s.sendall(struct.pack(">IHHQQI", _NBD_REQUEST_MAGIC, 0, 1, 43, 0, 4))
        s.sendall(b"AAAA")
        _m, werr, _h = struct.unpack(">IIQ", _recv(s, 16))
        assert werr != 0

        s.sendall(struct.pack(">IHHQQI", _NBD_REQUEST_MAGIC, 0, 2, 0, 0, 0))
        s.close()
    finally:
        srv.shutdown()
        srv.server_close()
        img.close()
