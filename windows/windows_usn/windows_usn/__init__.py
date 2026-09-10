r"""windows_usn - standalone NTFS change-journal ($UsnJrnl:$J) parser / carver.

Reads a ``$J`` data stream that has been extracted to a file, and also
**carves** ``USN_RECORD`` structures out of a raw volume image, a
``$UsnJrnl`` file with slack, or unallocated space - recovering change
records that are no longer in the live journal.

Per record: USN, timestamp (FILETIME, UTC), the file and parent ``$MFT``
reference (entry + sequence), the decoded reason flags, the source-info
flags, the file attributes and the file name.  Consecutive records for
the same file are folded into one **operation** (create / rename A->B /
delete / data-write / attribute-change).  With ``--mft`` the parent
reference is resolved to a full path.

Flags executables / scripts created in a user-writable path, create-then-
delete within seconds, mass-delete bursts, attribute-only changes
(timestomp-adjacent) and journal gaps.  Pure standard library, read-only.
"""

__version__ = "0.1.0"
