"""The collection engine: resolve targets -> enumerate files -> read -> sink."""

from __future__ import annotations

import glob
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from acquisition_collect.hashing import MultiHasher
from acquisition_collect.paths import (
    HostContext,
    UnknownVariableError,
    expand_path,
    long_path,
    strip_long_prefix,
)
from acquisition_collect.readers.base import Reader, ReadError
from acquisition_collect.report import ManifestRow, Report
from acquisition_collect.targets import Target


@dataclass
class CollectOptions:
    hashes: tuple[str, ...] = ("sha1",)
    max_bytes: int | None = None          # skip files larger than this
    dedupe: bool = True
    follow_symlinks: bool = False
    dry_run: bool = False


def _output_relpath(source_path: str) -> PurePosixPath:
    s = strip_long_prefix(source_path)
    drive, tail = os.path.splitdrive(s)
    if drive:
        root = drive.rstrip(":\\/") or "DRIVE"
    else:
        root = "ROOT"
    parts = [p for p in tail.replace("\\", "/").split("/") if p and p != ".."]
    # NTFS ADS such as "$UsnJrnl:$J" -> "$UsnJrnl__J" (":" illegal in output)
    parts = [p.replace(":", "__") for p in parts]
    return PurePosixPath(root, *parts)


class Sink:
    def add(self, rel: PurePosixPath, stream, hasher: MultiHasher,
            mtime: datetime | None) -> tuple[str, int]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class DirSink(Sink):
    def __init__(self, base: Path, subdir: str) -> None:
        self.base = base / subdir
        self.base.mkdir(parents=True, exist_ok=True)

    def add(self, rel, stream, hasher, mtime):
        dest = self.base / rel
        dest_s = long_path(dest)
        os.makedirs(os.path.dirname(dest_s), exist_ok=True)
        written = 0
        with open(dest_s, "wb", buffering=0) as out:
            for chunk in stream.chunks():
                hasher.update(chunk)
                out.write(chunk)
                written += len(chunk)
        if mtime is not None:
            ts = mtime.timestamp()
            try:
                os.utime(dest_s, (ts, ts))
            except OSError:
                pass
        return str(dest), written


class ZipSink(Sink):
    def __init__(self, zip_path: Path, subdir: str) -> None:
        self.subdir = subdir.strip("/")
        self._zf = zipfile.ZipFile(
            long_path(zip_path), "w", compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
        )

    def add(self, rel, stream, hasher, mtime):
        arc = f"{self.subdir}/{rel.as_posix()}"
        dt = (mtime or datetime.now(timezone.utc))
        zi = zipfile.ZipInfo(arc, date_time=dt.timetuple()[:6])
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o600 << 16
        written = 0
        with self._zf.open(zi, "w") as out:
            for chunk in stream.chunks():
                hasher.update(chunk)
                out.write(chunk)
                written += len(chunk)
        return arc, written

    def close(self):
        self._zf.close()


class Collector:
    def __init__(
        self,
        ctx: HostContext,
        reader: Reader,
        sink: Sink,
        report: Report,
        options: CollectOptions,
        logger,
    ) -> None:
        self.ctx = ctx
        self.reader = reader
        self.sink = sink
        self.report = report
        self.opt = options
        self.log = logger
        self._seen: set[str] = set()

    # -- enumeration -----------------------------------------------------
    def _iter_candidates(self, pattern: str, recursive: bool):
        has_glob = any(ch in pattern for ch in "*?[")
        if has_glob:
            rec = recursive or "**" in pattern
            for hit in glob.iglob(long_path(pattern), recursive=rec):
                yield strip_long_prefix(hit)
            return

        lp = long_path(pattern)
        if not os.path.exists(lp):
            return
        if os.path.isdir(lp):
            if recursive:
                for root, _dirs, files in os.walk(
                    lp, followlinks=self.opt.follow_symlinks
                ):
                    for fn in files:
                        yield strip_long_prefix(os.path.join(root, fn))
            else:
                try:
                    with os.scandir(lp) as it:
                        for e in it:
                            if e.is_file(follow_symlinks=self.opt.follow_symlinks):
                                yield strip_long_prefix(e.path)
                except OSError:
                    return
        else:
            yield pattern

    # -- collection ----------------------------------------------------
    def run(self, targets: list[Target]) -> None:
        self.report.stats.targets_matched = len(targets)
        for target in targets:
            self.log.info("Target: %s (%s)", target.name, target.id)
            for spec in target.paths:
                self._collect_spec(target, spec)

    def _collect_spec(self, target: Target, spec) -> None:
        try:
            patterns = expand_path(spec.path, self.ctx)
        except UnknownVariableError as e:
            self.report.add_error(target.id, spec.path, "expand",
                                  f"unknown variable {e}")
            self.log.warning("  %s: unknown variable %s", target.id, e)
            return

        if not patterns:
            self.log.debug("  %s: no profiles / no expansion for %s",
                           target.id, spec.path)
            return

        for pattern in patterns:
            found_any = False
            for src in self._iter_candidates(pattern, spec.recursive):
                found_any = True
                self._collect_one(target, src)
            if not found_any:
                self.log.debug("  %s: nothing matched %s", target.id, pattern)

    def _collect_one(self, target: Target, source_path: str) -> None:
        key = source_path.lower() if os.name == "nt" else source_path
        if self.opt.dedupe and key in self._seen:
            return
        self._seen.add(key)

        try:
            st = self.reader.stat(source_path)
        except ReadError as e:
            self.report.add_error(target.id, source_path, "stat", str(e))
            return

        if self.opt.max_bytes is not None and st.st_size > self.opt.max_bytes:
            self.log.debug("  skip (>%d bytes): %s", self.opt.max_bytes,
                           source_path)
            self.report.add_error(
                target.id, source_path, "size",
                f"{st.st_size} bytes exceeds --max-size",
            )
            return

        rel = _output_relpath(source_path)
        if self.opt.dry_run:
            self.log.info("  [dry-run] would collect %s (%d bytes)",
                          source_path, st.st_size)
            self.report.stats.files_collected += 1
            self.report.stats.bytes_collected += st.st_size
            return

        try:
            stream = self.reader.open(source_path)
        except ReadError as e:
            self.report.add_error(target.id, source_path, "open", str(e))
            self.log.warning("  open failed: %s (%s)", source_path, e)
            return

        hasher = MultiHasher(self.opt.hashes)
        try:
            out_path, written = self.sink.add(
                rel, stream, hasher, stream.times.modified
            )
        except (OSError, ReadError) as e:
            stream.close()
            self.report.add_error(target.id, source_path, "read", str(e))
            self.log.warning("  read failed: %s (%s)", source_path, e)
            return

        self.report.add_file(ManifestRow(
            target_id=target.id,
            target_name=target.name,
            category=target.category,
            source_path=source_path,
            output_path=out_path,
            size_bytes=written,
            backend=stream.backend,
            locked_fallback=stream.locked_fallback,
            hashes=hasher.hexdigests(),
            created_utc=stream.times.created,
            modified_utc=stream.times.modified,
            accessed_utc=stream.times.accessed,
            changed_utc=stream.times.changed,
            collected_utc=datetime.now(timezone.utc),
        ))
        self.log.info("  collected %s (%d bytes)", source_path, written)
