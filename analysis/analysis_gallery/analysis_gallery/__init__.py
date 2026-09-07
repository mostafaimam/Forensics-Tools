"""analysis_gallery - picture and video gallery for an evidence set.

Walks a folder or mounted image, finds every image and video **by content
signature** (extension-independent), and for each one pulls out:

* format, pixel dimensions, size, SHA-256;
* EXIF / QuickTime metadata - capture timestamp, camera make / model, lens,
  exposure, orientation, software;
* GPS position (decimal latitude / longitude, altitude) when present;
* an embedded thumbnail, or a coarse decoded one, for a contact sheet.

With ``--phash`` it computes a perceptual hash (dHash) for each still image
and groups visually near-identical pictures - resized copies, re-saves,
watermark crops - that a byte-hash would miss.

Output is CSV / JSON, or a single self-contained HTML contact sheet
(``--html``).  Pure standard library, no third-party imaging packages: the
JPEG / PNG / GIF / BMP decoders needed for hashing and thumbnails are
implemented in-tree.
"""

__version__ = "0.1.0"
