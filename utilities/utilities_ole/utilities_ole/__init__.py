r"""utilities_ole - OLE2 / compound-file and Office metadata extraction.

A standalone reader for the OLE2 Compound File Binary format ([MS-CFB]) and
for OOXML (`.docx` / `.xlsx` / `.pptx`) packages.  It lists the stream /
storage tree, parses the ``SummaryInformation`` /
``DocumentSummaryInformation`` property sets (and the OOXML core / app /
custom properties) into named fields - author, dates, template, last saved
by, revision, total editing time - detects and **decompresses VBA macro
source** ([MS-OVBA]), lists embedded objects, and pulls external
relationship targets (remote templates, linked content).

Flags macro auto-exec / shell / download constructs, remote templates,
author vs. last-saver mismatch and embedded objects.  Also the shared
compound-file library the other tools import.
"""

__version__ = "0.1.0"
