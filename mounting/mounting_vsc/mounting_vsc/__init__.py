r"""mounting_vsc - best-effort Volume Shadow Copy (VSS) discovery.

**Confidence & Validation - read before relying on this.** The
16-byte VSS identifier GUID this scan looks for
(``3808876B-C176-4E48-B7AE-04046E6CC752``) is a well-established
constant, widely cited across public DFIR research on the format. What
comes *after* that GUID in each VSS block - the catalog/store header's
exact field order, sizes, and offsets - is known only through
community reverse-engineering (the libvshadow project) with no public
vendor specification, and this project has no verified reference to
check its recollection of the exact byte layout against.

Given that, v0.1 deliberately does **not** implement full VSS
block-remapping / snapshot mounting: getting the differential-block
overlay logic wrong would silently serve corrupted bytes as if they
were valid historical file content - a materially worse failure mode
than a mislabeled metadata field, since corrupted "recovered" evidence
can look entirely legitimate to a reviewer. Instead, this reports every
VSS identifier hit found (a real, high-confidence signal that shadow
copies exist and roughly where their structures sit) plus *candidate*
fields nearby - FILETIME-shaped 8-byte values in a plausible date
range, and raw header bytes for GUID-sized spans - for the examiner to
judge, the same "candidates, not confident claims" pattern
`mounting_fvde` uses for CoreStorage's key-wrap plist. Treat every
candidate field as a lead requiring corroboration (e.g. against
`vssadmin list shadows` on a live system, or a reference tool), not as
verified ground truth.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
