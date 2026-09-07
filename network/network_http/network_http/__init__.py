"""network_http - carve HTTP transfers out of a packet capture.

Reassembles TCP streams from a ``pcap`` / ``pcapng``, parses the HTTP/1.x
messages in each direction (``Content-Length``, ``chunked`` and
connection-close framing; ``gzip`` / ``deflate`` decoded), and pairs each
request with its response.

For every transaction it records the method, URL, status, headers, the
size and **SHA-256 of the transferred body**, and - with ``--extract`` -
writes the body to disk (the file name comes from
``Content-Disposition``, then the URL, then a generated name).  Uploaded
request bodies are carved too.

Executables, scripts and archives on the wire, and bodies whose magic
bytes disagree with the ``Content-Type``, are flagged.
"""

__version__ = "0.1.0"
