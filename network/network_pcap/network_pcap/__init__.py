"""network_pcap - read a packet capture and summarise what happened.

A pure standard-library reader for classic ``pcap`` (microsecond and
nanosecond, both byte orders) and ``pcapng`` files.  It decodes Ethernet /
Linux-cooked / raw-IP / loopback framing down to IPv4 / IPv6 and
TCP / UDP / ICMP, then:

* reassembles packets into bidirectional **flows** (5-tuple) with byte and
  packet counts each way, duration and TCP handshake / teardown state;
* extracts **DNS** queries and answers, and **HTTP** request lines, hosts
  and response codes;
* flags cleartext credentials, plaintext protocols, DNS to look-alike or
  DGA-style names, likely tunnelling, port scans and long-lived or
  high-egress flows.

No third-party capture library.
"""

__version__ = "0.1.0"
