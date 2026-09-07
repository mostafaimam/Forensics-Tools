"""analysis_view - review any tabular evidence in one place.

Loads CSV / TSV / JSON / JSONL and basic ``.xlsx`` files, merges them into
one table (with a ``_source`` column), and produces a **self-contained
interactive HTML review page**: per-column filters, full-text search,
multi-column sort, column show / hide, conditional row colouring, and -
saved back into a sidecar file so the work survives - **tags, a notes
column and a reviewed flag** per row.

The same operations are available headless (``--filter``, ``--sort``,
``--export``) and in a ``tkinter`` window (``--gui``).  It generalises the
``analysis_timeline`` viewer to any table.
"""

__version__ = "0.1.0"
