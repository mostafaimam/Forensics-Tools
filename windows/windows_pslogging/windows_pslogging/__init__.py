r"""windows_pslogging - PowerShell forensics.

Reassembles PowerShell **ScriptBlock logging** (event 4104) across its
multi-part records, pulls **Module logging** (4103) and the pipeline
events, reads the classic ``Windows PowerShell`` log (400 / 500 / 600),
and parses on-disk ``PowerShell_transcript.*`` files.

Then it decodes the payloads that turn up inside:

* ``-EncodedCommand`` / ``-enc`` -> base64 -> UTF-16LE;
* ``[Convert]::FromBase64String("...")`` blobs;
* base64 + ``GZipStream`` / ``DeflateStream`` compressed commands.

One row per reassembled script or event: time (UTC), computer, user,
host application, the (decoded) script text, and the flags raised -
download cradles, AMSI / ETW bypass strings, obfuscation markers, hidden
windows, reflective loads, credential access and reverse-shell sockets.

Pure standard library (the EVTX / BinXml parser is vendored); read-only.
"""

__version__ = "0.1.0"
