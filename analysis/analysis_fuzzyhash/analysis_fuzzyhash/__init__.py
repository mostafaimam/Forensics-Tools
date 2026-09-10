r"""analysis_fuzzyhash - similarity hashing and clustering.

Computes, for a file set:

* **CTPH** - a context-triggered piecewise hash (the ssdeep construction:
  a rolling window picks reset points, each piece is FNV-hashed to one
  base64 character, at two block sizes).  Two CTPH digests are compared by
  a normalised edit distance -> a 0-100 similarity score.
* a **locality digest** - a byte-trigram histogram folded to quartile bits,
  compared by L1 distance (a TLSH-style whole-file similarity that, unlike
  CTPH, degrades gracefully with size differences).
* **imphash** and **rich-header hash** for PE files.

Then clusters the set: every pair scoring at or above ``--threshold`` is
unioned, and each cluster is reported with its members and a representative.
Finds near-duplicates and variant families that exact hashing misses.
"""

__version__ = "0.1.0"
