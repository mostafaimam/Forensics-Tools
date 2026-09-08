"""network_arp - IP <-> MAC <-> hostname <-> time mapping.

Builds an address-binding timeline from ARP / neighbour tables, DHCP
lease data and ARP frames in a capture:

* ISC ``dhcpd.leases`` and the Windows DHCP audit CSV
* ``arp -a`` / ``ip neigh`` / Windows ``arp -a`` text dumps
* ARP request / reply frames (and passive src-MAC/src-IP bindings) from a
  ``pcap`` / ``pcapng``

Answers "which host held this IP, with which MAC, at what time" and flags
address conflicts, gratuitous ARP and locally-administered MACs.  Pure
standard library.
"""

__version__ = "0.1.0"
