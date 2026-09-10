"""linux_packages - package install / upgrade / remove history.

Parses the package-manager logs under a mounted image or a live root
into one normalised timeline of package events:

* dpkg  - ``/var/log/dpkg.log*`` (+ rotated / ``.gz``)
* apt   - ``/var/log/apt/history.log*`` (Start-Date / Commandline /
  Requested-By / Install / Upgrade / Remove blocks)
* dnf / yum - ``/var/log/dnf.log*``, ``/var/log/dnf.rpm.log*``,
  ``/var/log/yum.log*`` (text), and ``/var/lib/dnf/history.sqlite``

Each event is ``(timestamp, action, package, version, from-version, arch,
source, requested-by, command)``.  Toolchain installs, network / recon
tooling, downgrades and manual out-of-repo ``.deb`` installs are flagged.
Pure standard library.
"""

__version__ = "0.1.0"
