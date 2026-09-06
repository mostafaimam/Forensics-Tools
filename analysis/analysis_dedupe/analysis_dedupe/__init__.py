"""analysis_dedupe - hash-based deduplication and 'distinct files' sets.

Hashes a collection (size-collision pre-filter for speed), groups files by
content, and reports duplicate sets, the reclaimable bytes, and a
one-representative-per-unique-content list.  ``--against`` diffs a target set
against a baseline to show what is new.
"""

__version__ = "0.1.0"
