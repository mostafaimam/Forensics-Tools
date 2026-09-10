"""linux_sshkeys - review SSH keys, known hosts and sshd configuration.

Inventories, from a mounted image or a live root, every:

* ``authorized_keys`` (system-wide and per-user) - options (``command=``,
  ``from=``, ``no-pty`` ...), key type, bit size, comment and the
  SHA256 / MD5 fingerprints;
* host key (``/etc/ssh/ssh_host_*_key.pub``) and the matching private key
  (format + whether it is passphrase-encrypted; key material is never
  parsed);
* ``known_hosts`` entry - hostnames (hashed entries are noted, not
  reversed), ``@cert-authority`` / ``@revoked`` markers, key type and
  fingerprint;
* ``sshd_config`` (+ ``sshd_config.d/*.conf`` and ``Match`` blocks) -
  every directive, with a review of the risky ones.

Flags wildcard ``from=``, forced ``command=``, weak / short keys, CA trust
lines, world-writable key files, permissive ``PermitRootLogin`` /
``PasswordAuthentication`` / forwarding settings and more.  Pure standard
library.
"""

__version__ = "0.1.0"
