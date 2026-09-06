"""analysis_index - full-text index and search over a file collection.

``analysis_index build`` walks a set of paths, extracts text (plain text and
markup directly, Office documents via their XML, everything else via ASCII +
UTF-16 string carving), and writes an on-disk inverted index (SQLite, no FTS
extension required).  ``analysis_index search`` (also installed as
``analysis_search``) runs boolean / phrase / proximity / regex queries and
returns matching files with keyword-in-context snippets.
"""

__version__ = "0.1.0"
