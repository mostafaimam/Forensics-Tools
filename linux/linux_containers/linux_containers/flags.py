"""Heuristic flags for a container record."""

from __future__ import annotations

import re

_SENSITIVE_HOST_PATHS = (
    "/", "/etc", "/root", "/home", "/boot", "/proc", "/sys", "/dev",
    "/var/lib", "/var/lib/docker", "/var/lib/containers", "/var/run",
    "/run", "/usr", "/lib", "/lib/modules", "/var/log",
)
_DOCKER_SOCK = re.compile(r"/(docker|containerd|crio|podman)\.sock$|"
                          r"docker\.sock")
_DANGER_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
                "DAC_READ_SEARCH", "BPF", "SYS_BOOT", "ALL"}
_SECRET_ENV = re.compile(r"^(.*_)?(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|"
                         r"ACCESS_?KEY|PRIVATE_?KEY|AUTH|CREDENTIAL|"
                         r"SESSION|PAT)S?=", re.I)
_CRADLE = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sh|bash)\b|"
                     r"/dev/tcp/|bash\s+-i|\bnc\b\s+-|\bncat\b|base64\s+-d",
                     re.I)


def _is_sensitive(host_path: str) -> bool:
    hp = host_path.rstrip("/") or "/"
    return hp in _SENSITIVE_HOST_PATHS or hp.startswith(
        ("/etc/", "/root/", "/proc/", "/sys/", "/boot/", "/dev/"))


def flag(c) -> list[str]:
    out: list[str] = []

    if c.privileged:
        out.append("privileged container (near-full host access)")

    for m in c.mounts:
        if _DOCKER_SOCK.search(m.source or "") or \
                _DOCKER_SOCK.search(m.dest or ""):
            out.append("container-runtime socket mounted (host takeover)")
        elif m.type == "bind" and _is_sensitive(m.source or ""):
            out.append(f"sensitive host path bind-mounted ({m.source} -> "
                       f"{m.dest})")
        elif m.type == "device":
            out.append(f"host device exposed ({m.source})")

    nm = (c.network_mode or "").lower()
    if nm in ("host",) or nm.startswith("host"):
        out.append("host network namespace (--network=host)")
    if (c.pid_mode or "").lower().startswith("host"):
        out.append("host PID namespace (--pid=host)")
    if (c.ipc_mode or "").lower().startswith("host"):
        out.append("host IPC namespace (--ipc=host)")

    dcaps = sorted(set(x.upper() for x in c.cap_add) & _DANGER_CAPS)
    if dcaps:
        out.append("dangerous capability added (" + ", ".join(dcaps) + ")")

    for so in c.security_opt:
        s = so.lower()
        if "apparmor" in s and "unconfined" in s:
            out.append("AppArmor disabled (apparmor=unconfined)")
        elif "seccomp" in s and "unconfined" in s:
            out.append("seccomp disabled (seccomp=unconfined)")
        elif "no-new-privileges" in s and ("false" in s or "0" in s):
            out.append("no-new-privileges explicitly disabled")

    if c.user in ("", "0", "root"):
        out.append("runs as root inside the container")

    for e in c.env:
        if _SECRET_ENV.match(e):
            k = e.split("=", 1)[0]
            out.append(f"secret-looking environment variable ({k})")

    joined = f"{c.entrypoint} {c.command}"
    if _CRADLE.search(joined):
        out.append("cradle / reverse-shell in the entrypoint / command")

    if c.image and (c.image.endswith(":latest") or ":" not in c.image.split(
            "/")[-1]):
        out.append(f"image pinned loosely ({c.image or '<none>'})")
    if re.search(r"(^|/)(\d{1,3}\.){3}\d{1,3}(:\d+)?/", c.image or ""):
        out.append(f"image from a raw-IP registry ({c.image})")

    if c.restart_policy in ("always", "unless-stopped"):
        out.append(f"restart policy '{c.restart_policy}' (survives reboot)")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "privileged container": "high",
    "container-runtime socket mounted": "high",
    "sensitive host path bind-mounted": "high",
    "host device exposed": "medium",
    "host network namespace": "medium",
    "host PID namespace": "high",
    "host IPC namespace": "medium",
    "dangerous capability added": "high",
    "AppArmor disabled": "medium",
    "seccomp disabled": "medium",
    "no-new-privileges explicitly disabled": "medium",
    "runs as root inside the container": "low",
    "secret-looking environment variable": "medium",
    "cradle / reverse-shell in the entrypoint": "high",
    "image pinned loosely": "low",
    "image from a raw-IP registry": "medium",
    "restart policy": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
