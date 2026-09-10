r"""macos_tcc - the TCC.db privacy-permission database.

Reads the Transparency, Consent and Control databases:

* ``/Library/Application Support/com.apple.TCC/TCC.db`` - the system
  store (Full Disk Access, Accessibility, Screen Recording, ...);
* ``~/Library/Application Support/com.apple.TCC/TCC.db`` - the per-user
  store (Camera, Microphone, Contacts, Automation, ...).

One row per grant: the scope (system / user), the service in plain
language (``kTCCServiceScreenCapture`` -> "Screen Recording"), the client
(bundle id or absolute path), the decision (allowed / denied / limited),
the ``last_modified`` time (Unix -> UTC), the indirect object for
Automation grants (the app being controlled), and whether it came from a
configuration profile / MDM.

Handles the several schema versions (``auth_value`` on modern macOS,
``allowed`` on older).  Flags high-impact permissions granted to a
command-line tool / script interpreter, keystroke-monitoring
(``kTCCServiceListenEvent``) grants, and clients that are an absolute
path in a user-writable location.  Pure standard library, read-only.
"""

__version__ = "0.1.0"
