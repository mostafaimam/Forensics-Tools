"""Parsers for authorized_keys / known_hosts / host keys / private keys."""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass, field

_KEY_TYPES = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
}
_WEAK_TYPES = {"ssh-dss"}


@dataclass
class SshKey:
    kind: str = ""              # authorized_key | known_host | host_key
    source: str = ""            # file path
    user: str = ""              # owning user for authorized_keys
    line: int = 0
    marker: str = ""            # @cert-authority | @revoked
    hosts: str = ""             # known_hosts host list (or "<hashed>")
    hashed_host: bool = False
    options: str = ""           # authorized_keys options blob
    key_type: str = ""
    bits: int = 0
    comment: str = ""
    sha256: str = ""            # SHA256:...
    md5: str = ""               # MD5:aa:bb:..
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "kind": self.kind, "user": self.user, "source": self.source,
            "line": self.line or "", "marker": self.marker,
            "hosts": self.hosts, "options": self.options,
            "key_type": self.key_type, "bits": self.bits or "",
            "comment": self.comment, "sha256": self.sha256, "md5": self.md5,
            "notable": ";".join(self.notable),
        }


def _fingerprints(blob: bytes) -> tuple[str, str]:
    if not blob:
        return "", ""
    s = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    m = hashlib.md5(blob).hexdigest()
    md5 = ":".join(m[i:i + 2] for i in range(0, len(m), 2))
    return f"SHA256:{s}", f"MD5:{md5}"


def _rsa_bits(blob: bytes) -> int:
    """For an ssh-rsa blob, the modulus length in bits."""
    try:
        off = 0
        (n,) = struct.unpack_from(">I", blob, off)
        off += 4 + n                        # "ssh-rsa"
        (elen,) = struct.unpack_from(">I", blob, off)
        off += 4 + elen                     # exponent
        (mlen,) = struct.unpack_from(">I", blob, off)
        off += 4
        m = blob[off:off + mlen].lstrip(b"\x00")
        return len(m) * 8
    except struct.error:
        return 0


def _decode_blob(b64: str) -> bytes:
    try:
        return base64.b64decode(b64, validate=False)
    except (ValueError, base64.binascii.Error):
        return b""


_OPT_SPLIT = re.compile(r'''((?:[^,"]|"[^"]*")+)''')


def _split_key_line(line: str):
    """Return (options, type, b64, comment) from one key line."""
    parts = line.split()
    # find the key-type token; everything before it is the options blob
    idx = next((i for i, p in enumerate(parts)
                if p in _KEY_TYPES or p.startswith(("ssh-", "ecdsa-", "sk-"))),
               None)
    if idx is None or idx + 1 >= len(parts):
        return "", "", "", ""
    options = " ".join(parts[:idx])
    key_type = parts[idx]
    b64 = parts[idx + 1]
    comment = " ".join(parts[idx + 2:])
    return options, key_type, b64, comment


def parse_authorized_keys(text: str, source: str, user: str) -> list[SshKey]:
    out: list[SshKey] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        options, kt, b64, comment = _split_key_line(line)
        if not kt:
            continue
        blob = _decode_blob(b64)
        sha, md5 = _fingerprints(blob)
        k = SshKey(kind="authorized_key", source=source, user=user, line=n,
                   options=options, key_type=kt, comment=comment,
                   sha256=sha, md5=md5)
        if kt == "ssh-rsa":
            k.bits = _rsa_bits(blob)
        out.append(k)
    return out


_HASHED = re.compile(r"^\|1\|[^|]+\|[^|]+$")


def parse_known_hosts(text: str, source: str) -> list[SshKey]:
    out: list[SshKey] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        marker = ""
        if parts and parts[0] in ("@cert-authority", "@revoked"):
            marker, parts = parts[0], parts[1:]
        if len(parts) < 3:
            continue
        hosts, kt, b64 = parts[0], parts[1], parts[2]
        hashed = bool(_HASHED.match(hosts))
        blob = _decode_blob(b64)
        sha, md5 = _fingerprints(blob)
        k = SshKey(kind="known_host", source=source, line=n, marker=marker,
                   hosts="<hashed>" if hashed else hosts, hashed_host=hashed,
                   key_type=kt, comment=" ".join(parts[3:]),
                   sha256=sha, md5=md5)
        if kt == "ssh-rsa":
            k.bits = _rsa_bits(blob)
        out.append(k)
    return out


def parse_host_pub(text: str, source: str) -> SshKey | None:
    line = text.strip()
    if not line:
        return None
    _o, kt, b64, comment = _split_key_line(line)
    if not kt:
        return None
    blob = _decode_blob(b64)
    sha, md5 = _fingerprints(blob)
    k = SshKey(kind="host_key", source=source, key_type=kt, comment=comment,
               sha256=sha, md5=md5)
    if kt == "ssh-rsa":
        k.bits = _rsa_bits(blob)
    return k


@dataclass
class PrivateKey:
    source: str = ""
    fmt: str = ""               # openssh | pem-rsa | pem-ec | pkcs8 | putty
    encrypted: bool = False
    cipher: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {"kind": "private_key", "source": self.source, "fmt": self.fmt,
                "encrypted": "yes" if self.encrypted else "no",
                "cipher": self.cipher, "notable": ";".join(self.notable)}


def parse_private_key(text: str, source: str) -> PrivateKey | None:
    head = text[:4000]
    pk = PrivateKey(source=source)
    if "BEGIN OPENSSH PRIVATE KEY" in head:
        pk.fmt = "openssh"
        try:
            b64 = "".join(l for l in head.splitlines()
                          if l and "BEGIN" not in l and "END" not in l)
            raw = base64.b64decode(b64 + "===", validate=False)
            if raw.startswith(b"openssh-key-v1\x00"):
                off = 15
                (clen,) = struct.unpack_from(">I", raw, off)
                cipher = raw[off + 4:off + 4 + clen].decode("ascii", "replace")
                pk.cipher = cipher
                pk.encrypted = cipher != "none"
        except (struct.error, ValueError):
            pass
    elif "BEGIN RSA PRIVATE KEY" in head or "BEGIN EC PRIVATE KEY" in head or \
            "BEGIN DSA PRIVATE KEY" in head:
        pk.fmt = "pem-" + ("rsa" if "RSA" in head else
                           "ec" if "EC" in head else "dsa")
        pk.encrypted = "Proc-Type:" in head and "ENCRYPTED" in head
        m = re.search(r"DEK-Info:\s*([A-Z0-9-]+)", head)
        if m:
            pk.cipher = m.group(1)
    elif "BEGIN ENCRYPTED PRIVATE KEY" in head:
        pk.fmt, pk.encrypted = "pkcs8", True
    elif "BEGIN PRIVATE KEY" in head:
        pk.fmt = "pkcs8"
    elif "PuTTY-User-Key-File" in head:
        pk.fmt = "putty"
        pk.encrypted = bool(re.search(r"Encryption:\s*(?!none)\S+", head))
    else:
        return None
    return pk
