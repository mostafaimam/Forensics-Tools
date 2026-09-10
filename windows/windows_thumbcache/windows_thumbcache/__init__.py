r"""windows_thumbcache - parse thumbcache_*.db and thumbcache_idx.db.

Reads the Windows Explorer thumbnail cache
(``…\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db``):

* each ``thumbcache_<size>.db`` holds ``CMMM`` cache entries - a 64-bit
  cache id, an identifier string (a path or the id in hex, depending on
  the Windows version), the thumbnail dimensions, and the thumbnail image
  itself (JPEG / PNG / BMP);
* ``thumbcache_idx.db`` is the index - it maps each cache id to the cache
  sizes that hold it, an entry-flags value and the **source file's
  last-modified time** (FILETIME, UTC).

One row per cached thumbnail: cache id, identifier, format, dimensions,
data size, which ``.db`` it came from and (from the index) the last-
modified time.  ``--extract DIR`` writes every thumbnail out as an image
file - **evidence of pictures that may no longer be on disk**.

Flags identifiers that point at a removable / user-writable / UNC path
and thumbnails whose data does not match a known image format.  Pure
standard library, read-only.
"""

__version__ = "0.1.0"
