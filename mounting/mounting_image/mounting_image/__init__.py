"""mounting_image - read-only access to forensic disk images.

Presents raw / split-raw / EWF (``E01``) / VHD / VHDX / VMDK containers as a
single seekable byte stream, enumerates their MBR / GPT partitions, and can
export the whole disk or one partition as raw bytes, stream a byte range, or
serve it read-only over NBD (attachable with ``nbd-client`` on Linux, or any
NBD-aware tool elsewhere).
"""

__version__ = "0.1.0"
