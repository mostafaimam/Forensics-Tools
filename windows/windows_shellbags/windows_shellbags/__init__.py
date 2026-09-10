r"""windows_shellbags - reconstruct the shellbag folder-access tree.

Walks ``BagMRU`` / ``Bags`` from ``UsrClass.dat`` (and the older
``NTUSER.DAT`` locations) and rebuilds the tree of folders the user has
browsed in Explorer, one row per folder:

* the **full reconstructed path** (assembled from the shell items along
  the BagMRU branch);
* the shell-item type (drive, directory, GUID/known folder, network
  share, zip, control panel, ...);
* the BagMRU key path, its ``NodeSlot`` and its **last-written time**
  (the best available "folder last interacted" timestamp);
* the folder's own created / modified / accessed DOS timestamps and the
  ``$MFT`` entry + sequence from the ``BEEF0004`` extension block, when
  present;
* the ``MRUListEx`` position (how recently that child was touched
  relative to its siblings).

Flags folders on removable / network / UNC paths, browsing inside an
archive, access to another user's profile, ``AppData`` / ``Temp`` /
``ProgramData`` / ``$Recycle.Bin`` paths, mounted image / VHD roots and
GUID-only entries that no longer resolve.  Pure standard library (the
``regf`` hive parser and the shell-item parser are vendored).
"""

__version__ = "0.1.0"
