r"""windows_recentfilecache - RecentFileCache.bcf parser.

``C:\Windows\AppCompat\Programs\RecentFileCache.bcf`` is the Windows 7
program-execution artefact that Amcache replaced.  It is a 20-byte header
followed by a flat list of length-prefixed UTF-16 paths - every executable
the Program Compatibility Assistant saw run (or newly appear) in roughly
the 24 hours before the last program-inventory sweep.

The file carries no timestamps of its own; bound the activity with the
file's own MFT timestamps.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
