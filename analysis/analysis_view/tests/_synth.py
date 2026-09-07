"""Minimal .xlsx writer for the test-suite (no openpyxl)."""

from __future__ import annotations

import zipfile

_CONTENT_TYPES = """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>"""

_RELS = """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

_WB = """<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"""

_WB_RELS = """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>"""

_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _col_letter(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, header, rows):
    strings: list[str] = []
    idx: dict[str, int] = {}

    def sid(v: str) -> int:
        if v not in idx:
            idx[v] = len(strings)
            strings.append(v)
        return idx[v]

    sheet_rows = []
    grid = [header] + [[str(c) for c in r] for r in rows]
    for ri, row in enumerate(grid, 1):
        cells = "".join(
            f'<c r="{_col_letter(ci)}{ri}" t="s"><v>{sid(val)}</v></c>'
            for ci, val in enumerate(row))
        sheet_rows.append(f'<row r="{ri}">{cells}</row>')
    sheet = (f'<?xml version="1.0"?><worksheet xmlns="{_NS}"><sheetData>'
             + "".join(sheet_rows) + "</sheetData></worksheet>")
    shared = (f'<?xml version="1.0"?><sst xmlns="{_NS}" count="{len(strings)}" '
              f'uniqueCount="{len(strings)}">'
              + "".join(f"<si><t>{_x(s)}</t></si>" for s in strings) + "</sst>")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("xl/workbook.xml", _WB)
        z.writestr("xl/_rels/workbook.xml.rels", _WB_RELS)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        z.writestr("xl/sharedStrings.xml", shared)
    return path


def _x(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
