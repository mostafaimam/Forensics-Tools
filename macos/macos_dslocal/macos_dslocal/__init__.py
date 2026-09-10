r"""macos_dslocal - local account records from /var/db/dslocal.

Reads the Directory Services local node:

* ``/private/var/db/dslocal/nodes/Default/users/*.plist``
* ``/private/var/db/dslocal/nodes/Default/groups/*.plist``

Each user plist is decoded into one row: name, uid, gid, real name, home,
shell, ``generateduid``, the **password hint**, which authentication
mechanisms are configured (``ShadowHash`` / ``KerberosKeys`` /
``SRP`` / a legacy crypt hash / none), and - from the embedded
``ShadowHashData`` and ``accountPolicyData`` binary plists - the
PBKDF2 iteration count, the account creation time, the last successful /
failed login, the failed-login count and the last password change
(all UTC).  **No hash material is printed and nothing is cracked.**

Group membership is resolved, and each user is tagged with the groups it
belongs to (``admin`` in particular).

Flags passwordless accounts, hidden non-service accounts, non-Apple
members of ``admin``, uid 0 accounts other than ``root``, password hints
that look like passwords, and homes outside ``/Users``.  Pure standard
library (``plistlib``), read-only.
"""

__version__ = "0.1.0"
