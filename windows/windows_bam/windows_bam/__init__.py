r"""windows_bam - Background / Desktop Activity Moderator last-execution data.

Reads a ``SYSTEM`` hive and pulls the per-user last-run timestamps that
Windows 10/11 keeps under:

    SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\<exe path>
    SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>\<exe path>

(and the flatter ``...\bam\UserSettings\<SID>`` layout used by Windows 10
1709).  Each value's name is the full NT path of an executable; the first
8 bytes of its data are the **last-execution time** (FILETIME, UTC).

One row per (SID, executable): the resolved drive path, the last-run
time, which moderator (bam / dam) and which control set it came from.
Flags executables in a user-writable path, living-off-the-land binaries,
UNC paths and names that masquerade as a system binary.  Pure standard
library (the ``regf`` parser is vendored); read-only.
"""

__version__ = "0.1.0"
