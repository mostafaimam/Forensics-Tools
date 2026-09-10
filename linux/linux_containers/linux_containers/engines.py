"""Per-engine collectors: Docker, Podman, containerd."""

from __future__ import annotations

import json
from pathlib import Path

from linux_containers.model import Container, Mount


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _join(v) -> str:
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v or "")


# ---------------------------------------------------------------- Docker
def _docker_ports(port_bindings: dict) -> list[str]:
    out = []
    for cport, binds in (port_bindings or {}).items():
        for b in binds or []:
            hip = b.get("HostIp", "") or "0.0.0.0"
            out.append(f"{hip}:{b.get('HostPort', '')}->{cport}")
    return out


def docker(root: Path) -> list[Container]:
    base = root / "var/lib/docker/containers"
    if not base.is_dir():
        return []
    repos = _load(root / "var/lib/docker/image/overlay2/repositories.json") \
        or _load(root / "var/lib/docker/image/aufs/repositories.json") or {}
    id_to_name = {}
    for _repo, tags in (repos.get("Repositories", {}) or {}).items():
        for tag, digest in tags.items():
            id_to_name[digest] = tag

    out = []
    for cdir in sorted(base.iterdir()):
        cfg = _load(cdir / "config.v2.json")
        if not cfg:
            continue
        c = Container(engine="docker", id=cfg.get("ID", cdir.name),
                      source=str(cdir / "config.v2.json"))
        conf = cfg.get("Config", {}) or {}
        st = cfg.get("State", {}) or {}
        c.name = (cfg.get("Name", "") or "").lstrip("/")
        c.image = conf.get("Image", "")
        c.image_id = cfg.get("Image", "")
        if not c.image and c.image_id in id_to_name:
            c.image = id_to_name[c.image_id]
        c.created = cfg.get("Created", "")
        c.started_at = st.get("StartedAt", "") or ""
        c.finished_at = st.get("FinishedAt", "") or ""
        c.state = ("running" if st.get("Running") else
                   "paused" if st.get("Paused") else
                   "restarting" if st.get("Restarting") else "exited")
        c.exit_code = str(st.get("ExitCode", "")) if not st.get("Running") \
            else ""
        c.error = st.get("Error", "") or ""
        c.entrypoint = _join(conf.get("Entrypoint")) or cfg.get("Path", "")
        c.command = _join(conf.get("Cmd")) or _join(cfg.get("Args"))
        c.env = list(conf.get("Env", []) or [])
        c.user = conf.get("User", "") or ""
        c.labels = dict(conf.get("Labels", {}) or {})

        for dest, mp in (cfg.get("MountPoints", {}) or {}).items():
            c.mounts.append(Mount(
                source=mp.get("Source", "") or mp.get("Name", ""),
                dest=mp.get("Destination", dest),
                mode="rw" if mp.get("RW", True) else "ro",
                type=mp.get("Type", "")))

        hc = _load(cdir / "hostconfig.json") or {}
        c.privileged = bool(hc.get("Privileged"))
        c.cap_add = list(hc.get("CapAdd", []) or [])
        c.security_opt = list(hc.get("SecurityOpt", []) or [])
        c.network_mode = hc.get("NetworkMode", "") or ""
        c.pid_mode = hc.get("PidMode", "") or ""
        c.ipc_mode = hc.get("IpcMode", "") or ""
        rp = hc.get("RestartPolicy", {}) or {}
        c.restart_policy = rp.get("Name", "") or ""
        c.ports = _docker_ports(hc.get("PortBindings", {}))
        for b in hc.get("Binds", []) or []:
            parts = b.split(":")
            if len(parts) >= 2 and not any(m.source == parts[0]
                                           for m in c.mounts):
                c.mounts.append(Mount(source=parts[0], dest=parts[1],
                                      mode=parts[2] if len(parts) > 2 else "rw",
                                      type="bind"))
        for d in hc.get("Devices", []) or []:
            c.mounts.append(Mount(source=d.get("PathOnHost", ""),
                                  dest=d.get("PathInContainer", ""),
                                  type="device"))

        log = cdir / f"{c.id}-json.log"
        if log.is_file():
            c.log_file = str(log)
        out.append(c)
    return out


# ---------------------------------------------------------------- Podman
def _oci_config(spec: dict, c: Container):
    proc = spec.get("process", {}) or {}
    c.command = _join(proc.get("args"))
    c.entrypoint = c.entrypoint or ""
    c.env = list(proc.get("env", []) or []) or c.env
    u = proc.get("user", {}) or {}
    if "uid" in u:
        c.user = str(u["uid"])
    caps = proc.get("capabilities", {}) or {}
    bounding = caps.get("bounding", []) or caps.get("effective", []) or []
    # only surface the notable ones; a full default set is ~14 caps
    c.cap_add = [x.replace("CAP_", "") for x in bounding
                 if x.replace("CAP_", "") in _NOTABLE_CAPS]
    for m in spec.get("mounts", []) or []:
        dst = m.get("destination", "")
        src = m.get("source", "")
        if m.get("type") in ("proc", "sysfs", "tmpfs", "mqueue", "devpts",
                             "cgroup") and src in ("proc", "sysfs", "tmpfs",
                                                   "mqueue", "devpts",
                                                   "cgroup"):
            continue
        opts = m.get("options", []) or []
        c.mounts.append(Mount(source=src, dest=dst,
                              mode="ro" if "ro" in opts else "rw",
                              type=m.get("type", "bind")))
    # In the OCI spec a namespace type that is ABSENT from the list is shared
    # with the host; present-without-path means a fresh private namespace;
    # present-with-path means it joins that specific namespace.
    ns_list = (spec.get("linux", {}) or {}).get("namespaces", None)
    if ns_list is not None:
        present = {n.get("type", ""): n for n in ns_list}
        for t, setter in (("network", "network_mode"), ("pid", "pid_mode"),
                          ("ipc", "ipc_mode")):
            if t not in present:
                setattr(c, setter, "host")
            elif present[t].get("path"):
                path = present[t]["path"]
                if "/proc/1/ns/" in path:
                    setattr(c, setter, "host")
                else:
                    setattr(c, setter, f"container:{path}")
    lx = spec.get("linux", {}) or {}
    if lx.get("apparmorProfile", "") == "unconfined" or \
            spec.get("process", {}).get("apparmorProfile", "") == "unconfined":
        c.security_opt.append("apparmor=unconfined")
    # an explicit empty seccomp object == seccomp disabled; a missing key
    # means the runtime applies its own default, which we do not flag.
    if "seccomp" in lx and not lx.get("seccomp"):
        c.security_opt.append("seccomp=unconfined")


_NOTABLE_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
                 "NET_ADMIN", "NET_RAW", "DAC_READ_SEARCH", "DAC_OVERRIDE",
                 "SETUID", "SETGID", "BPF", "PERFMON", "SYS_BOOT", "MKNOD",
                 "AUDIT_CONTROL", "ALL"}


def podman(root: Path) -> list[Container]:
    storage = root / "var/lib/containers/storage/overlay-containers"
    if not storage.is_dir():
        storage = root / "var/lib/containers/storage/vfs-containers"
    cj = _load(storage / "containers.json") if storage.is_dir() else None
    if not cj:
        return []
    imgs = _load(root / "var/lib/containers/storage/overlay-images/"
                 "images.json") or []
    img_names = {}
    for im in imgs:
        for n in im.get("names", []) or []:
            img_names[im.get("id", "")] = n

    out = []
    for entry in cj:
        c = Container(engine="podman", id=entry.get("id", ""),
                      source=str(storage / "containers.json"))
        names = entry.get("names", []) or []
        c.name = names[0] if names else ""
        c.image_id = entry.get("image", "")
        c.image = img_names.get(c.image_id, "")
        c.created = entry.get("created", "") or ""
        meta = entry.get("metadata", "")
        if isinstance(meta, str) and meta.startswith("{"):
            try:
                m = json.loads(meta)
                c.image = c.image or m.get("image-name", "")
                c.name = c.name or m.get("name", "")
            except ValueError:
                pass
        ud = storage / entry.get("id", "") / "userdata"
        spec = _load(ud / "config.json")
        if spec:
            c.source = str(ud / "config.json")
            _oci_config(spec, c)
            ann = spec.get("annotations", {}) or {}
            if ann.get("io.kubernetes.cri-o.PrivilegedRuntime") == "true" or \
                    ann.get("io.podman.annotations.privileged") == "TRUE":
                c.privileged = True
            c.image = c.image or ann.get("io.podman.annotations.image", "")
        st = _load(ud / "state.json") or {}
        c.state = st.get("status", "") or ("created" if not spec else "")
        for lg in ("ctr.log", "conmon.log"):
            if (ud / lg).is_file():
                c.log_file = str(ud / lg)
                break
        out.append(c)
    return out


# ------------------------------------------------------------- containerd
def containerd(root: Path) -> list[Container]:
    base = root / "var/lib/containerd/io.containerd.runtime.v2.task"
    if not base.is_dir():
        base = root / "run/containerd/io.containerd.runtime.v2.task"
    if not base.is_dir():
        return []
    out = []
    for ns_dir in sorted(base.iterdir()) if base.is_dir() else []:
        if not ns_dir.is_dir():
            continue
        for cdir in sorted(ns_dir.iterdir()):
            spec = _load(cdir / "config.json")
            if not spec:
                continue
            c = Container(engine="containerd", id=cdir.name,
                          name=cdir.name, source=str(cdir / "config.json"))
            ann = spec.get("annotations", {}) or {}
            c.image = ann.get("io.kubernetes.cri.image-name", "") or \
                ann.get("io.containerd.image.name", "")
            c.name = ann.get("io.kubernetes.cri.container-name", "") or c.name
            _oci_config(spec, c)
            if (cdir / "log.json").is_file() or (cdir / "log").is_file():
                c.log_file = str(cdir / "log")
            out.append(c)
    return out
