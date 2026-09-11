r"""windows_sqlmap - locate SQLite databases and process them with named maps.

Walks a target for files carrying the SQLite header (``SQLite format 3``),
regardless of extension, and - for each one - tries every **map**: a small
declarative profile (JSON) naming the tables a schema must have, a SQL
query, the output columns, and the time format of the timestamp column.
A match runs the query and normalises the rows; a database matching no
map is still listed, with a table/row-count summary so it can be reviewed
by hand (``--dump-table``).

A handful of maps ship built in (Skype classic ``main.db``, Windows Sticky
Notes ``plum.sqlite``); ``--map-dir`` adds more without touching the code.
This is the long-tail-app-database engine: most desktop apps that are not
covered by a dedicated parser keep their data in SQLite, and the schema is
usually just a SELECT away once you know the table names.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
