"""memory_image - identify, map and convert RAM dumps.

Presents a physical-memory dump (raw / LiME / ELF core / Windows crash dump)
as one addressable space - ``read_physical(addr, size)`` with zero-fill for
gaps - reports its format, physical range map and OS hints, and converts
between raw / LiME / padded layouts or carves out a region.

The :class:`~memory_image.loader.MemoryImage` class is the shared loader the
other ``memory_*`` tools build on.
"""

__version__ = "0.1.0"
