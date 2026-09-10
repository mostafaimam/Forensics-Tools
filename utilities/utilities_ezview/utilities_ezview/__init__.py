r"""utilities_ezview - zero-dependency viewer for common document formats.

Sniffs a file by content (not just extension) and renders it as text:
plain text / logs (with encoding detection), CSV / TSV tables, HTML and
MHTML (tag-stripped), RTF, and best-effort text extraction from OOXML
(`.docx` / `.xlsx` / `.pptx`), legacy OLE Office (`.doc` / `.xls`) and
PDF.  Anything it cannot render is handed to the ``utilities_hex`` dump +
data-interpreter view.
"""

__version__ = "0.1.0"
