"""mounting_partitions - map the partition layout of a disk image.

Opens a raw / split / EWF / VHD / VMDK image (or an ``nbd://`` URL),
parses the MBR (including extended / logical partitions) and the GPT, and
prints one clean layout table: index, scheme, start / end / size, the
partition type, the label, and - by peeking at the first sectors of each
slice - the **filesystem or container actually present** (NTFS, FAT,
exFAT, ext2-4, XFS, Btrfs, APFS, HFS+, LVM2, LUKS, BitLocker, swap, …).

Gaps and overlaps between partitions, and unpartitioned space at the
start / end of the disk, are reported.  This tool never mounts anything -
use ``mounting_image`` for that.  Pure standard library, read-only.
"""

__version__ = "0.1.0"
