r"""windows_sigma - a lightweight Sigma-style detection-rules engine.

Runs Sigma-shaped YAML detection rules (a small bundled ruleset, plus
``--rule-dir`` for more) against the normalised CSV / JSON output of
``windows_evtx`` / ``windows_pslogging`` and reports each hit with the
rule name, level and matched fields.

Implements the common subset: a hand-rolled indentation-based YAML reader
(mappings / lists / scalars - no anchors, flow style, or block scalars),
the ``detection`` block (named selections + a ``condition`` expression
supporting ``and`` / ``or`` / ``not`` / parentheses / ``1 of`` / ``all
of`` with ``*`` wildcards), and the field modifiers ``|contains`` /
``|startswith`` / ``|endswith`` / ``|re`` / ``|all``. A field's own value
may use ``*`` / ``?`` glob wildcards, matching Sigma's default semantics.

Logsource matching is best-effort: rows are matched against a rule's
``logsource.service`` by which of the suite's tools produced them
(``windows_evtx`` for ``security`` / ``system`` / ``sysmon``,
``windows_pslogging`` for ``powershell``); a rule with no recognised
service is tried against every row.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
