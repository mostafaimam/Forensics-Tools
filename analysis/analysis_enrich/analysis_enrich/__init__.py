r"""analysis_enrich - post-process an analysis_timeline bundle.

Reads a timeline (the ``analysis_timeline`` CSV / JSONL) and **adds
columns** rather than rewriting rows:

* ``ioc`` / ``ioc_source`` - IPs, domains, URLs and hashes in the event
  matched against supplied feeds (plain list, CSV, or STIX-lite JSON);
* ``attack`` - MITRE ATT&CK technique ids from a bundled map keyed by the
  tool / artefact / command patterns the suite emits;
* ``geo`` - a coarse registry-region for public IPs from a bundled table
  (or a user ``--geo-csv`` of ``cidr,country``);
* ``known`` - ``good`` / ``bad`` / ``unknown`` for hashes, from a
  ``--known-csv`` (e.g. an ``analysis_kff`` export).

Enrichers are independent and each only appends; the original rows and
ordering are preserved.
"""

__version__ = "0.1.0"
