"""analysis_kff - Known File Filter.

Import hash sets (NSRL RDS text or SQLite, Project VIC / CAID JSON, HashKeeper,
plain hash lists) into a local SQLite index, then classify files or a list of
hashes as **known-good** (filter out), **known-bad** / **notable** (alert), or
**unknown**.
"""

__version__ = "0.1.0"
