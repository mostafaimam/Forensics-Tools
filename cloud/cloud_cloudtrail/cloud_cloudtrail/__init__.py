"""cloud_cloudtrail - normalise AWS CloudTrail logs into one row per API
call.

Reads CloudTrail's standard delivery format: JSON files (optionally
gzip-compressed, as S3 delivers them) each holding a top-level
``{"Records": [...]}`` array. The record schema (``eventTime``,
``eventName``, ``userIdentity``, ``requestParameters``,
``responseElements``, ...) is AWS's own long-stable, publicly
documented format - unlike several of this suite's memory-forensics and
container formats, there is no undocumented-structure caveat here.
Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
