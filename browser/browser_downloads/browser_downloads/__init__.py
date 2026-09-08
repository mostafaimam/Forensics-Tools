"""browser_downloads - every recorded file download, cross-referenced to disk.

Reads the download history from the Chromium family (`History.downloads`
+ `downloads_url_chains`) and Firefox (`places.sqlite` annotations and
the legacy `downloads.sqlite` / `moz_downloads`), then correlates it
with the filesystem:

* ``.crdownload`` / ``.part`` / ``.download`` leftovers - interrupted or
  in-progress transfers
* the NTFS ``:Zone.Identifier`` alternate data stream - Mark-of-the-Web
  ZoneId / ReferrerUrl / HostUrl on the saved file

Every download becomes one normalised row: source and referring URL,
saved path, byte counts, danger verdict, state, MIME, and - when the file
is present - its size and SHA-256.  Executables, double extensions,
MIME / extension mismatches and raw-IP sources are flagged.
"""

__version__ = "0.1.0"
