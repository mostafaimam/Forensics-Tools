"""memory_strings - address-aware string extraction from a RAM dump.

Pulls ASCII and UTF-16LE string runs out of a physical-memory dump (raw /
LiME / ELF core / Windows crash dump), tags each with the physical address it
was found at, and classifies it against a built-in pattern library (URLs,
emails, IPs, hostnames, registry keys, file / UNC paths, GUIDs, command
lines, base64 blobs, private keys, wallet addresses, …).
"""

__version__ = "0.1.0"
