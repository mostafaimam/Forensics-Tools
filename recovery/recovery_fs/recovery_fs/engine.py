"""Common file-system entry model and the backend interface."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FsEntry:
    path: str                 # forward-slash path, no leading slash
    name: str
    is_dir: bool
    size: int
    allocated: bool           # False = deleted / unallocated
    inode: int = 0            # MFT record / cluster / inode number
    created: str = ""
    modified: str = ""
    accessed: str = ""
    changed: str = ""         # MFT-changed / ctime
    fs: str = ""
    extra: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "path": self.path, "name": self.name,
            "type": "dir" if self.is_dir else "file",
            "size": self.size,
            "allocated": "yes" if self.allocated else "DELETED",
            "inode": self.inode, "created": self.created,
            "modified": self.modified, "accessed": self.accessed,
            "changed": self.changed, "fs": self.fs,
        }

    def bodyfile(self) -> str:
        """The 3.x bodyfile / mactime pipe format."""
        def epoch(iso):
            if not iso:
                return 0
            from datetime import datetime, timezone
            try:
                return int(datetime.fromisoformat(
                    iso.replace("Z", "+00:00")).replace(
                    tzinfo=timezone.utc).timestamp())
            except ValueError:
                return 0
        mode = "d/drwxr-xr-x" if self.is_dir else "r/rrwxrwxrwx"
        name = self.path + ("  (deleted)" if not self.allocated else "")
        return "|".join(str(x) for x in (
            "", name, self.inode, mode, 0, 0, self.size,
            epoch(self.accessed), epoch(self.modified),
            epoch(self.changed), epoch(self.created)))


class Backend:
    fs_name = "?"

    def entries(self, *, include_deleted=True):
        raise NotImplementedError

    def read(self, entry: FsEntry) -> bytes:
        raise NotImplementedError

    def close(self):
        pass
