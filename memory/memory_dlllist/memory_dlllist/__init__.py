"""memory_dlllist - loaded modules per process from a Windows RAM dump.

Pool-tag scanning for image / mapped-file VADs (``Vad``, ``Vadl``).  For
each one the backing file's full path is recovered by chasing
``_MMVAD -> Subsection -> ControlArea -> FileObject -> FileName`` (newer
Windows 10 builds also expose the ``FileObject`` directly), and the region
is attributed to a process by testing candidate directory-table bases.

No per-build symbol profile.  Modules loaded from user-writable
directories, system DLLs on the wrong path, and executable image regions
with **no backing file** (manual maps / hollowing) are flagged.
"""

__version__ = "0.1.0"
