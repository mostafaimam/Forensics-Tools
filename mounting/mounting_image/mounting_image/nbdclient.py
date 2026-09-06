"""A built-in NBD (Network Block Device) client.

Two things:

* :class:`NBDClient` speaks the NBD fixed-newstyle protocol over a socket -
  ``read`` / ``flush`` / ``disconnect`` - and doubles as an
  :class:`~mounting_image.formats.base.Image` so a remote export can be
  inspected (``partitions``), streamed (``pull``) or carved from on **any**
  OS with no external tools.

* :func:`attach_linux` binds the negotiated socket to ``/dev/nbdN`` with the
  kernel ``nbd`` module's ioctls - the same job ``nbd-client`` does - so on
  Linux the export becomes a real read-only block device with nothing but
  Python.  (Windows / macOS have no kernel NBD; use ``pull`` there.)
"""

from __future__ import annotations

import os
import socket
import struct
import threading

from mounting_image.formats.base import Image, ImageError

_NBDMAGIC = b"NBDMAGIC"
_IHAVEOPT = b"IHAVEOPT"
_CLISERV_MAGIC = 0x00420281861253
_REQUEST_MAGIC = 0x25609513
_SIMPLE_REPLY_MAGIC = 0x67446698

NBD_FLAG_C_FIXED_NEWSTYLE = 1
NBD_FLAG_C_NO_ZEROES = 2
NBD_FLAG_READ_ONLY = 2

NBD_OPT_EXPORT_NAME = 1
NBD_OPT_ABORT = 2

NBD_CMD_READ = 0
NBD_CMD_FLUSH = 3
NBD_CMD_DISC = 2

# Linux <linux/nbd.h> ioctls (all _IO(0xab, n), no size field)
NBD_SET_SOCK = 0xAB00
NBD_SET_BLKSIZE = 0xAB01
NBD_SET_SIZE = 0xAB02
NBD_DO_IT = 0xAB03
NBD_CLEAR_SOCK = 0xAB04
NBD_CLEAR_QUE = 0xAB05
NBD_SET_SIZE_BLOCKS = 0xAB07
NBD_DISCONNECT = 0xAB08
NBD_SET_TIMEOUT = 0xAB09
NBD_SET_FLAGS = 0xAB0A


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ImageError("NBD server closed the connection")
        buf += chunk
    return buf


class NBDClient(Image):
    format_name = "nbd"

    def __init__(self, host: str, port: int = 10809, name: str = "",
                 timeout: float = 30.0):
        self.host = host
        self.port = port
        self.name = name
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        self.export_size = 0
        self.transmission_flags = 0
        self._handle = 0
        self._lock = threading.Lock()
        self._handshake()

    # -- handshake -------------------------------------------------
    def _handshake(self) -> None:
        s = self._sock
        if _recvn(s, 8) != _NBDMAGIC:
            raise ImageError("not an NBD server (bad magic)")
        style = _recvn(s, 8)
        if style == _IHAVEOPT:
            _hsflags = struct.unpack(">H", _recvn(s, 2))[0]
            s.sendall(struct.pack(">I", NBD_FLAG_C_FIXED_NEWSTYLE))
            nm = self.name.encode()
            s.sendall(_IHAVEOPT + struct.pack(">II", NBD_OPT_EXPORT_NAME,
                                              len(nm)) + nm)
            body = _recvn(s, 10)
            self.export_size, self.transmission_flags = struct.unpack(">QH", body)
            _recvn(s, 124)                        # reserved zeroes
        else:
            # oldstyle: magic(8) already read as `style`? re-handle
            raise ImageError("oldstyle NBD servers are not supported")
        if not self.export_size:
            raise ImageError("NBD server reported a zero-length export")

    # -- Image interface -----------------------------------------
    @property
    def size(self) -> int:
        return self.export_size

    @property
    def read_only(self) -> bool:
        return bool(self.transmission_flags & NBD_FLAG_READ_ONLY)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ImageError("negative offset")
        if offset >= self.export_size:
            return b""
        length = min(length, self.export_size - offset)
        out = bytearray()
        with self._lock:
            pos = offset
            remaining = length
            while remaining > 0:
                n = min(remaining, 32 << 20)
                self._handle += 1
                h = self._handle
                self._sock.sendall(struct.pack(">IHHQQI", _REQUEST_MAGIC, 0,
                                               NBD_CMD_READ, h, pos, n))
                magic, err, rh = struct.unpack(">IIQ", _recvn(self._sock, 16))
                if magic != _SIMPLE_REPLY_MAGIC or rh != h:
                    raise ImageError("desynchronised NBD reply")
                if err:
                    raise ImageError(f"NBD read error {err} at offset {pos}")
                out += _recvn(self._sock, n)
                pos += n
                remaining -= n
        return bytes(out)

    def flush(self) -> None:
        if not (self.transmission_flags & 4):
            return
        with self._lock:
            self._handle += 1
            h = self._handle
            self._sock.sendall(struct.pack(">IHHQQI", _REQUEST_MAGIC, 0,
                                           NBD_CMD_FLUSH, h, 0, 0))
            _recvn(self._sock, 16)

    def disconnect(self) -> None:
        try:
            with self._lock:
                self._sock.sendall(struct.pack(">IHHQQI", _REQUEST_MAGIC, 0,
                                               NBD_CMD_DISC, 0, 0, 0))
        except OSError:
            pass

    def close(self) -> None:
        self.disconnect()
        try:
            self._sock.close()
        except OSError:
            pass

    # -- streaming helper -------------------------------------
    def pull(self, out_path: str, *, offset: int = 0,
             length: int | None = None, progress=None) -> int:
        end = self.export_size if length is None else min(
            self.export_size, offset + length)
        written = 0
        with open(out_path, "wb") as fh:
            pos = offset
            while pos < end:
                n = min(1 << 20, end - pos)
                fh.write(self.read(pos, n))
                pos += n
                written += n
                if progress:
                    progress(written, end - offset)
        return written

    def detach_socket(self) -> socket.socket:
        """Hand the live socket to the caller (for kernel attach)."""
        s = self._sock
        self._sock = None
        return s


# ------------------------------------------------------------------
def parse_nbd_url(url: str) -> tuple[str, int, str]:
    """``nbd://host:port/export`` or ``host:port[/export]`` -> (host, port, name)."""
    raw = url
    if raw.startswith("nbd://"):
        raw = raw[6:]
    name = ""
    if "/" in raw:
        raw, name = raw.split("/", 1)
    host, _, port = raw.partition(":")
    return host or "127.0.0.1", int(port or 10809), name


def is_nbd_url(s: str) -> bool:
    if s.startswith("nbd://"):
        return True
    host, _, rest = s.partition(":")
    port = rest.split("/", 1)[0]
    return bool(host) and port.isdigit()


# ------------------------------------------------------------------
class LinuxAttachment:
    def __init__(self, device: str, nbd_fd: int, thread: threading.Thread):
        self.device = device
        self._fd = nbd_fd
        self._thread = thread

    def detach(self) -> None:
        import fcntl
        try:
            fcntl.ioctl(self._fd, NBD_DISCONNECT)
        except OSError:
            pass
        try:
            fcntl.ioctl(self._fd, NBD_CLEAR_SOCK)
        except OSError:
            pass
        try:
            os.close(self._fd)
        except OSError:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=5)


def detach_device(device: str) -> None:
    """Disconnect a /dev/nbdN that this or another process attached."""
    import fcntl
    fd = os.open(device, os.O_RDWR)
    try:
        try:
            fcntl.ioctl(fd, NBD_DISCONNECT)
        except OSError:
            pass
        try:
            fcntl.ioctl(fd, NBD_CLEAR_SOCK)
        except OSError:
            pass
    finally:
        os.close(fd)


def attach_linux(client: NBDClient, device: str = "/dev/nbd0", *,
                 block_size: int = 512, read_only: bool = True,
                 timeout: int = 30) -> LinuxAttachment:
    """Bind *client*'s connection to *device* via the kernel nbd module."""
    if not os.path.exists("/dev"):
        raise ImageError("attach_linux is only available on Linux")
    import fcntl
    if not os.path.exists(device):
        raise ImageError(
            f"{device} does not exist - run 'modprobe nbd' first "
            f"(needs root and the kernel 'nbd' module)")
    try:
        nbd_fd = os.open(device, os.O_RDWR)
    except OSError as e:
        raise ImageError(f"cannot open {device}: {e} (need root?)") from None

    sock = client.detach_socket()
    try:
        fcntl.ioctl(nbd_fd, NBD_SET_BLKSIZE, block_size)
        fcntl.ioctl(nbd_fd, NBD_SET_SIZE_BLOCKS, client.size // block_size)
        fcntl.ioctl(nbd_fd, NBD_CLEAR_SOCK)
        if timeout:
            try:
                fcntl.ioctl(nbd_fd, NBD_SET_TIMEOUT, timeout)
            except OSError:
                pass
        flags = 0
        if read_only or client.read_only:
            flags |= NBD_FLAG_READ_ONLY
            try:
                fcntl.ioctl(nbd_fd, 0x125D, 1)          # BLKROSET
            except OSError:
                pass
        try:
            fcntl.ioctl(nbd_fd, NBD_SET_FLAGS, flags)
        except OSError:
            pass
        fcntl.ioctl(nbd_fd, NBD_SET_SOCK, sock.fileno())
    except OSError as e:
        os.close(nbd_fd)
        raise ImageError(f"NBD ioctl failed on {device}: {e}") from None

    def _run():
        import fcntl as _f
        try:
            _f.ioctl(nbd_fd, NBD_DO_IT)
        except OSError:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return LinuxAttachment(device, nbd_fd, t)
