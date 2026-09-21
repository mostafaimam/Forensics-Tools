"""browser_shortcuts - Chromium omnibox-intent artifacts.

Reads three small Chromium SQLite stores that record browsing *intent*
rather than browsing *history*, and so often survive a "clear history"
that wipes ``History`` itself:

- ``Shortcuts`` (``omni_box_shortcuts``) - what the user typed in the
  address bar and which suggestion they picked, with a hit count and
  last-access time.
- ``Top Sites`` (``top_sites``) - the "frequently visited" tiles shown
  on a new tab, ranked.
- ``Network Action Predictor`` (``network_action_predictor``) - per-
  typed-prefix hit/miss counts the browser uses to decide whether to
  pre-resolve/pre-connect a predicted destination.

All three are separate SQLite files under a Chromium profile directory,
independent of ``History``. Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
