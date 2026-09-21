"""cloud_gws - normalise Google Workspace audit activity (Admin SDK
Reports API JSON export, or the Admin console's equivalent) into one
row per event.

An "activity" record can carry several events; this expands each into
its own row, flattening the actor/IP/application-level fields alongside
the event's own name and parameters. The Reports API's activity schema
(``id``/``actor``/``ipAddress``/``events``/``parameters``) is Google's
own long-stable, publicly documented format for the core envelope;
exact parameter names for less-common event categories carry somewhat
lower confidence than that envelope - see the README. Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
