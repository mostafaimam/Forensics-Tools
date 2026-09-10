r"""utilities_strings - string extraction with a forensic pattern library.

Pulls ASCII and UTF-16 (LE / BE) strings out of any file, image or device,
with byte offsets, and classifies each against a built-in library of ~35
forensic patterns: URLs, emails, IPv4 / IPv6, hostnames, UNC / Windows /
Unix paths, registry paths, GUIDs, PowerShell / cmd one-liners, base64
blobs, private keys, cloud / API tokens, JWTs, crypto-wallet addresses,
credit cards (Luhn-checked), SSNs, IBANs, MAC addresses, ``.onion``
hosts, and known offensive-tooling markers.

``--category`` / ``--pattern`` narrow the output to a class; ``--grep`` is
a free-text filter.  CSV / JSON carry the offset, encoding, string and
match category.
"""

__version__ = "0.1.0"
