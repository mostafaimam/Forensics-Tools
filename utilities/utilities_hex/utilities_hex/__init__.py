r"""utilities_hex - hex viewer and cursor-driven data interpreter.

Pages through an arbitrarily large file, image or device; renders the
classic ``offset  16 bytes  ASCII`` view; searches for hex / text / regex;
and interprets the bytes at any offset as signed / unsigned ints (8-64,
LE + BE), float / double, a GUID, an RGB / RGBA colour, and every common
timestamp encoding (Unix, Windows FILETIME, DOS, OLE automation date,
Cocoa / Mac-absolute, HFS+, WebKit / Chrome).

``interpret_at`` and the ``tkinter`` widget are importable, so the suite's
other GUIs embed the same data-interpreter panel.
"""

__version__ = "0.1.0"
