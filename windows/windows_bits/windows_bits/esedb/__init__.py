"""windows_bits.esedb - a standalone, dependency-free ESE / JET (.edb) reader.

Parses the Extensible Storage Engine database format used by SRUM
(``SRUDB.dat``), the WinINET cache (``WebCacheV01.dat``), the Microsoft
User Access Log (``*.mdb``), Windows Search (``Windows.edb``) and others.

What it does:

* reads the database header (page size, format version, state);
* walks the B-tree of any table from its FDP page;
* parses the catalog (``MSysObjects``) into tables, columns and long-value
  trees;
* decodes leaf records into ``{column: value}`` using the fixed / variable
  / tagged data layout, including the Vista+ extended tagged format
  (separated long values, multi-values, 7-bit compression);
* assembles long values from the long-value tree.

Column types, timestamp conversion (OLE automation date and FILETIME) and
the catalog are all handled.  Pure standard library; read-only.

Used by :mod:`windows_srum`, :mod:`windows_webcache` and
:mod:`windows_usbdevices` (which vendor this package).
"""

__version__ = "0.1.0"

from windows_bits.esedb.database import EseDatabase, EseError   # noqa: E402,F401
