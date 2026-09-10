r"""macos_installhistory - InstallHistory.plist + /var/db/receipts.

Reads the two records macOS keeps of what has been installed:

* ``/Library/Receipts/InstallHistory.plist`` - the **install-event
  timeline**: one entry per install / update with the date, the display
  name and version, the package identifiers and the process that ran the
  install (``softwareupdated`` / ``installer`` / ``Installer`` /
  ``storedownloadd`` / a script);
* ``/private/var/db/receipts/*.plist`` - one **receipt per installed
  package** still on disk: the identifier, version, install date, the
  install prefix, the installing process and the ``.pkg`` file name.

The two are correlated: a receipt with no matching history entry (or the
reverse) is called out.

Flags packages installed by an unusual process, non-Apple packages
installed by ``installer`` from a ``.pkg`` in a download / temp folder,
configuration profiles (``.mobileconfig``), and receipts added recently
with no history entry.  Pure standard library (``plistlib``), read-only.
"""

__version__ = "0.1.0"
