"""utilities_hash - hash a file set / tree into a manifest, and verify it.

One streaming pass computes every requested digest (MD5 / SHA-1 / SHA-256 /
SHA-512 / SHA3-256 / BLAKE2b).  Output is a CSV / JSON manifest or the
plain ``<hash>  <path>`` format the ``*sum`` tools use.  ``--verify`` diffs
a tree against a prior manifest and reports added / removed / changed /
moved files - the integrity check that pairs with ``analysis_kff`` and
``acquisition_image``.
"""

__version__ = "0.1.0"
