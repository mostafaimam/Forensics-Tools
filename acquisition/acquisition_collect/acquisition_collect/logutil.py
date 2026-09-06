from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class UtcFormatter(logging.Formatter):
    """Formatter that always emits UTC ISO-8601 timestamps."""

    def formatTime(self, record, datefmt=None):  # noqa: N802
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime(datefmt or "%Y-%m-%dT%H:%M:%S.%fZ")


def setup_logging(logfile: Path | None, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("acquisition_collect")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = UtcFormatter("%(asctime)s  %(levelname)-7s  %(message)s")

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    if logfile is not None:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
