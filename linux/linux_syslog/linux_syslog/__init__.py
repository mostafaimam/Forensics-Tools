"""linux_syslog - normaliser for classic Linux text logs.

Reads ``syslog`` / ``messages`` / ``auth.log`` / ``secure`` and friends
(including rotated ``.1`` / ``.gz`` files), understands both the BSD
(RFC 3164) and the RFC 5424 line formats, and emits either a flat record
timeline or a stream of structured security events (SSH logins, sudo, su,
PAM failures, session open/close, cron, account changes).
"""

__version__ = "0.1.0"
