"""browser_cache - list and extract cached HTTP responses.

Reads the Chromium **Simple Cache** (``Cache/Cache_Data/<hash>_0`` entry
files - a from-scratch parser for the ``SimpleFileHeader`` /
``SimpleFileEOF`` layout and the ``HttpResponseInfo`` pickle) and the
Firefox **cache2** store (``cache2/entries/<sha1>`` - data followed by
metadata: hash chunks, header, key, and the ``response-head`` element).

Every cached object is one row: URL, HTTP status, content-type, size,
and the request / response / last-fetched / expiry timestamps.  With
``--extract`` the response bodies are written to disk (``gzip`` /
``br`` / ``deflate`` decoded where possible), each hashed with SHA-256.
Read-only.  Pure standard library.
"""

__version__ = "0.1.0"
