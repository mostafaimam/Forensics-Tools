"""Synthetic SSH material for the linux_sshkeys test-suite."""

from __future__ import annotations

import base64
import os
import struct
from pathlib import Path


def _s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _mpint(n: int) -> bytes:
    if n == 0:
        return _s(b"")
    length = (n.bit_length() + 8) // 8
    b = n.to_bytes(length, "big")
    return _s(b)


def ed25519_pub(seed: int = 1) -> str:
    blob = _s(b"ssh-ed25519") + _s(bytes((seed + i) % 256 for i in range(32)))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def rsa_pub(bits: int = 3072, seed: int = 3) -> str:
    n = (1 << (bits - 1)) | seed | 1
    blob = _s(b"ssh-rsa") + _mpint(65537) + _mpint(n)
    return "ssh-rsa " + base64.b64encode(blob).decode()


def dss_pub() -> str:
    blob = _s(b"ssh-dss") + _mpint(7) + _mpint(11) + _mpint(13) + _mpint(17)
    return "ssh-dss " + base64.b64encode(blob).decode()


def hashed_known_host_line(key: str) -> str:
    salt = base64.b64encode(os.urandom(20)).decode()
    h = base64.b64encode(os.urandom(20)).decode()
    return f"|1|{salt}|{h} {key}"


OPENSSH_PRIV_UNENC = """-----BEGIN OPENSSH PRIVATE KEY-----
""" + base64.b64encode(
    b"openssh-key-v1\x00" + _s(b"none") + _s(b"none") + _s(b"") + b"\x00\x00\x00\x01"
    + _s(b"\x00" * 40) + _s(b"\x00" * 40)).decode() + """
-----END OPENSSH PRIVATE KEY-----
"""

OPENSSH_PRIV_ENC = """-----BEGIN OPENSSH PRIVATE KEY-----
""" + base64.b64encode(
    b"openssh-key-v1\x00" + _s(b"aes256-ctr") + _s(b"bcrypt") + _s(b"salt")
    + b"\x00\x00\x00\x01" + _s(b"\x00" * 40) + _s(b"\x00" * 60)).decode() + """
-----END OPENSSH PRIVATE KEY-----
"""

PEM_RSA_UNENC = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END RSA PRIVATE KEY-----
"""

PEM_RSA_ENC = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF

U2FsdGVkX1+abcdefabcdefabcdefabcdefabcdef
-----END RSA PRIVATE KEY-----
"""

SSHD_CONFIG = """# managed
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysCommand /usr/local/bin/fetch-keys
AllowTcpForwarding yes
PermitTunnel yes
X11Forwarding yes
UsePAM yes
Ciphers aes128-ctr,3des-cbc
LogLevel QUIET
Subsystem sftp /usr/lib/openssh/sftp-server

Match User deploy
    ForceCommand /usr/bin/borg serve --restrict-to-path /backup
"""


def build_tree(root: Path) -> Path:
    good = ed25519_pub(1)
    weak_rsa = rsa_pub(1024, seed=5)
    dss = dss_pub()

    # root authorized_keys
    d = root / "root/.ssh"
    d.mkdir(parents=True)
    (d / "authorized_keys").write_text(
        f"{good} admin@corp\n"
        f'command="/usr/bin/rsync --server",no-pty,no-X11-forwarding '
        f'{ed25519_pub(9)} backup\n'
        f'from="10.0.0.0/8" {ed25519_pub(20)} restricted@corp\n'
        f'command="/bin/bash -i" {ed25519_pub(30)} pwn@kali\n'
        f'environment="LD_PRELOAD=/tmp/x.so" {ed25519_pub(40)} env-key\n'
        f"{weak_rsa} legacy\n")

    # a user with a backdoor-ish key and a private key
    u = root / "home/deploy/.ssh"
    u.mkdir(parents=True)
    (u / "authorized_keys").write_text(f"{ed25519_pub(50)} deploy@laptop\n")
    (u / "id_ed25519").write_text(OPENSSH_PRIV_UNENC)
    (u / "id_rsa").write_text(PEM_RSA_ENC)
    (u / "known_hosts").write_text(
        f"github.com {ed25519_pub(60)}\n"
        f"@cert-authority *.corp.example {rsa_pub(3072, seed=7)}\n"
        + hashed_known_host_line(ed25519_pub(70)) + "\n")

    # /etc/ssh
    e = root / "etc/ssh"
    e.mkdir(parents=True)
    (e / "ssh_host_ed25519_key.pub").write_text(f"{ed25519_pub(80)} root@host")
    (e / "ssh_host_rsa_key.pub").write_text(f"{rsa_pub(3072, seed=9)} root@host")
    (e / "ssh_host_dsa_key.pub").write_text(f"{dss} root@host")
    (e / "ssh_host_ed25519_key").write_text(OPENSSH_PRIV_ENC)
    (e / "sshd_config").write_text(SSHD_CONFIG)
    cd = e / "sshd_config.d"
    cd.mkdir()
    (cd / "10-hardening.conf").write_text("PermitRootLogin prohibit-password\n"
                                          "PermitUserEnvironment yes\n")
    return root
