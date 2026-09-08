"""network_dns - DNS activity from captures, resolver caches and hosts files.

Consolidates DNS evidence from three sources into one name-resolution
timeline:

* queries and answers carved from a ``pcap`` / ``pcapng``
* the OS resolver cache - Windows ``ipconfig /displaydns`` text and
  ``systemd-resolved`` dumps
* ``hosts`` files (static name overrides)

For every name it records first / last seen, the query types, the answers
and their TTLs, and the resolver.  Tunnelling, DGA-looking names,
suspicious record types and hosts-file overrides are flagged.
"""

__version__ = "0.1.0"
