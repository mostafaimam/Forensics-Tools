r"""windows_webcache - parse WebCacheV01.dat (the WinINET store).

Reads the ESE database that Internet Explorer, legacy Edge and every
WinINET-based application use for their history, cookies, cached content
and HTML5 DOM storage
(``…\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat``).

* the ``Containers`` table names each container (History, Cookies,
  Content, DOMStore, iedownload, …) and gives its on-disk directory;
* each ``Container_<n>`` table holds the entries - URL, local filename,
  entry size, access count, and the **modified / accessed / expiry /
  sync** FILETIMEs;
* history and cookie URLs are un-prefixed (``Visited: user@…`` ->
  ``…``, ``Cookie:user@domain/path`` -> host + path) and the entry is
  classified (history / cookie / content / download / dom-storage).

Flags downloads of executables / scripts, IP-literal or punycode hosts,
``file://`` URLs, paste / anonymiser / tunnel sites and cookies for those
domains.  Vendors :mod:`windows_esedb`; pure standard library, read-only.
"""

__version__ = "0.1.0"
