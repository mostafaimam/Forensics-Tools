"""linux_bashhist - shell and REPL history recovery across all users.

Finds every history file on a system (``bash`` / ``zsh`` / ``fish`` / ``sh`` /
``ash`` plus ``python`` / ``mysql`` / ``psql`` / ``sqlite`` / ``node`` /
``redis`` REPLs), parses the per-shell timestamp formats where present, merges
them into one ordered timeline, and flags commands that look like attacker
activity (download-and-run, reverse shells, base64 payloads, credential
access, log/history tampering).
"""

__version__ = "0.1.0"
