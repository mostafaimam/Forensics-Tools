"""The normalised container record."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Mount:
    source: str = ""
    dest: str = ""
    mode: str = ""          # rw | ro
    type: str = ""          # bind | volume | tmpfs

    def text(self) -> str:
        return f"{self.source}:{self.dest}:{self.mode or self.type}"


@dataclass
class Container:
    engine: str = ""              # docker | podman | containerd
    id: str = ""
    name: str = ""
    image: str = ""
    image_id: str = ""
    created: str = ""
    started_at: str = ""
    finished_at: str = ""
    state: str = ""               # running | exited | created
    exit_code: str = ""
    error: str = ""
    entrypoint: str = ""
    command: str = ""
    env: list = field(default_factory=list)
    mounts: list = field(default_factory=list)          # Mount
    ports: list = field(default_factory=list)           # "hostip:hport->cport/proto"
    privileged: bool = False
    cap_add: list = field(default_factory=list)
    security_opt: list = field(default_factory=list)
    network_mode: str = ""
    pid_mode: str = ""
    ipc_mode: str = ""
    user: str = ""
    restart_policy: str = ""
    labels: dict = field(default_factory=dict)
    log_file: str = ""
    source: str = ""              # the config file this came from
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "engine": self.engine, "id": self.id[:12], "name": self.name,
            "image": self.image, "image_id": self.image_id[:19],
            "state": self.state, "created": self.created,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "exit_code": self.exit_code, "entrypoint": self.entrypoint,
            "command": self.command,
            "env": " ".join(self.env),
            "mounts": ";".join(m.text() for m in self.mounts),
            "ports": ";".join(self.ports),
            "privileged": "yes" if self.privileged else "",
            "cap_add": ",".join(self.cap_add),
            "security_opt": ",".join(self.security_opt),
            "network_mode": self.network_mode, "pid_mode": self.pid_mode,
            "ipc_mode": self.ipc_mode, "user": self.user,
            "restart_policy": self.restart_policy,
            "labels": ";".join(f"{k}={v}" for k, v in self.labels.items()),
            "log_file": self.log_file, "source": self.source,
            "notable": ";".join(self.notable),
        }
