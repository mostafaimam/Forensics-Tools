"""linux_persistence - one sweep for every userland persistence vector.

Walks a mounted image or a live root and inventories, in a single
normalised finding list, the common Linux persistence mechanisms:

* shell login / rc files (``/etc/profile``, ``/etc/profile.d/*``,
  ``/etc/bash.bashrc``, ``~/.bashrc`` / ``.bash_profile`` / ``.profile``
  / ``.zshrc`` / ``.bash_logout``), ``/etc/environment``
* the dynamic loader: ``/etc/ld.so.preload``, ``/etc/ld.so.conf`` /
  ``ld.so.conf.d/*``, and ``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` set in any
  of the above
* ``rc.local`` / ``rc.d`` scripts, ``/etc/init.d/*``
* ``motd`` / ``/etc/update-motd.d/*``
* ``/etc/xinetd.conf`` / ``xinetd.d/*``, ``/etc/inetd.conf``
* PAM: any non-standard module line in ``/etc/pam.d/*``
* kernel modules: ``/etc/modules``, ``/etc/modules-load.d/*``,
  ``/etc/modprobe.d/*`` (``install`` / ``options`` lines)
* udev: ``RUN{...}`` / ``PROGRAM`` in ``/etc/udev/rules.d/*``,
  ``/lib/udev/rules.d/*``
* ``sudoers`` / ``sudoers.d/*`` - NOPASSWD, ``!authenticate``, command
  aliases to shells
* systemd generators (``/etc/systemd/system-generators/*``) and a light
  pass over ``/etc/systemd/system/*`` (``linux_units`` does the full job)
* cron: a light pass over the crontab locations (``linux_cron`` does the
  full job)

Each finding carries the mechanism, path, the payload line, the file
mtime, and a verdict.  Flags world-writable configs, files that are not
owned by any package's default set, inline shells / download cradles,
encoded payloads and loader hijacks.  Pure standard library.
"""

__version__ = "0.1.0"
