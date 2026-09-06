"""acquisition_image - create and verify forensic disk images.

Reads a source (a file, a partition/volume, or a whole physical disk) and
writes a forensically sound image - raw, split raw, or EWF (``E01``) - hashing
every byte as it goes, tolerating bad sectors, and producing an acquisition
log + JSON manifest.  A separate verification pass re-reads the written image
and compares hashes.
"""

__version__ = "0.1.0"
