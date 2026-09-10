"""linux_units - systemd unit-file inventory and persistence review.

Walks every systemd unit under a mounted image or a live root -
``/etc/systemd``, ``/usr/lib/systemd``, ``/lib/systemd``,
``/run/systemd`` and the per-user trees - merges each unit's drop-ins
(``*.d/*.conf``) and resolves its enable state from the ``.wants`` /
``.requires`` symlinks, then lists one row per unit: ``ExecStart``,
``Type``, ``User``, ``WantedBy``, enabled state, restart policy and the
drop-in chain.

Units whose ``ExecStart`` lives in a user-writable or temporary path,
runs an inline shell / download cradle, or is enabled without an
``[Install]`` section are flagged.  Pure standard library.
"""

__version__ = "0.1.0"
