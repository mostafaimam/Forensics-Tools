r"""macos_launchd - review LaunchAgents / LaunchDaemons persistence.

Reads every ``launchd`` job plist under a mounted macOS volume or a live
root:

* ``/Library/LaunchDaemons`` - root daemons
* ``/Library/LaunchAgents`` - agents for every user's login session
* ``~/Library/LaunchAgents`` - per-user agents
* ``/System/Library/Launch{Daemons,Agents}`` - Apple-shipped (noted as
  such)

Per job: the scope, the label, the resolved program / argument vector,
the run-as user, the triggers in plain language (``RunAtLoad``,
``StartInterval``, ``StartCalendarInterval``, ``WatchPaths``,
``KeepAlive``, ``StartOnMount``), the disabled flag, and the environment
variables.

Flags programs in a user-writable path, inline shells / download cradles,
``DYLD_INSERT_LIBRARIES`` injection, a label that does not match the
plist file name, a label masquerading as ``com.apple.*`` outside
``/System``, aggressive ``KeepAlive`` + ``RunAtLoad`` respawners and
world-writable plists.  Pure standard library (``plistlib``), read-only.
"""

__version__ = "0.1.0"
