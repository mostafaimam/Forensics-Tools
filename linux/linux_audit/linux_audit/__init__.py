"""linux_audit - normalise the Linux audit daemon (auditd) logs.

Reassembles the multi-line ``audit.log`` records by their
``msg=audit(<epoch>.<millis>:<serial>)`` event id into one normalised
event: the syscall and its outcome, the reconstructed command
(``EXECVE``), the executable, the decoded ``proctitle``, the touched
paths (``PATH``), the working directory (``CWD``), uid / auid / session,
the audit key(s), and, for the ``USER_*`` / ``AVC`` / account-management
record types, the relevant actor and result fields.

Hex-encoded fields (``proctitle``, ``EXECVE`` args, ``comm``, ...) are
decoded.  ``SOCKADDR`` records are decoded to an address and port.
Syscall numbers are mapped to names for the common architectures.

Flags privilege changes, auth failures, account changes, audit-rule
tampering, SELinux denials, execution from a writable path and recon /
download-cradle command lines.  Pure standard library.
"""

__version__ = "0.1.0"
