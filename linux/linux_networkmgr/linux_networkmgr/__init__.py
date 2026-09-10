"""linux_networkmgr - saved network configuration and joined networks.

Collects, from a mounted image or a live root:

* **NetworkManager** keyfile profiles
  (``/etc/NetworkManager/system-connections/*``) - id, uuid, type,
  autoconnect, last-used timestamp, Wi-Fi SSID / BSSID / mode, the
  security key-management and whether a PSK / 802.1x secret is stored in
  the file, IPv4 / IPv6 method + addresses + DNS + gateway + routes,
  proxy, cloned / spoofed MAC, and VPN service + gateway.
* **wpa_supplicant** - the ``network={...}`` blocks in
  ``/etc/wpa_supplicant/wpa_supplicant*.conf`` (SSID, key_mgmt, and
  whether a psk is present).
* **systemd-networkd** ``*.network`` units and a best-effort read of
  **netplan** ``*.yaml`` (addresses, gateway, nameservers, Wi-Fi access
  points).
* **/etc/hosts** and **/etc/resolv.conf**.

Secret *values* are never printed - only the fact that a secret is stored
in the clear.  Flags plaintext Wi-Fi / 802.1x / VPN secrets, autoconnect
to an open network, a spoofed MAC, a proxy / PAC URL, `/etc/hosts`
overrides of public domains and unexpected DNS servers.  Pure standard
library.
"""

__version__ = "0.1.0"
