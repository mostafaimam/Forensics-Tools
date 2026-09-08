"""network_logs - normalise firewall / proxy / IDS text logs.

One parser for the common network-log formats - iptables / nftables
kernel lines, ``pflog`` (tcpdump text), the Windows Firewall
``pfirewall.log``, Squid ``access.log``, Zeek ``conn.log`` (TSV) and
Suricata ``eve.json`` - emitting a single flow / event schema (time,
source, destination, ports, protocol, action, bytes, rule / signature)
that feeds ``analysis_timeline`` and correlates with pcap-derived data.

Pure standard library.
"""

__version__ = "0.1.0"
