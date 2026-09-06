"""Built-in registry plugins plus an external-plugin loader.

Import this package to get :data:`PLUGINS`, a mapping of ``id -> {"fn",
"description", "hives"}``.  Each built-in submodule registers its plugins via
the :func:`windows_registry.plugins._base.plugin` decorator on import.

External plugins: point ``--plugin-dir DIR`` at a folder of ``*.py`` files.
Each file is executed with ``plugin`` / ``RegistryHive`` and the helpers from
``_base`` available in its globals; anything it decorates with ``@plugin`` is
merged into :data:`PLUGINS`.
"""

from __future__ import annotations

import importlib
import runpy
from pathlib import Path

from windows_registry.plugins import _base
from windows_registry.plugins._base import (  # noqa: F401  (re-exported)
    ANY,
    PLUGINS,
    detect_hive_kind,
    plugin,
)

# import order defines the display order of --list-plugins
for _mod in ("ntuser", "software", "system", "sam", "security", "amcache",
             "usrclass"):
    try:
        importlib.import_module(f"{__name__}.{_mod}")
    except ModuleNotFoundError:
        pass


def load_external(dirs) -> list[str]:
    """Execute every ``*.py`` under each directory in *dirs*.

    Returns the list of plugin ids that were added.
    """
    before = set(PLUGINS)
    inject = {name: getattr(_base, name) for name in dir(_base)
              if not name.startswith("__")}
    for d in dirs or []:
        p = Path(d)
        files = [p] if p.is_file() else sorted(p.glob("*.py"))
        for f in files:
            if f.name.startswith("_"):
                continue
            try:
                runpy.run_path(str(f), init_globals=inject)
            except Exception as e:  # noqa: BLE001
                raise RuntimeError(f"failed to load plugin file {f}: {e}") from e
    return sorted(set(PLUGINS) - before)


def plugins_for(kind: str) -> list[str]:
    """Ids whose ``hives`` tuple matches *kind* (or that apply to ANY)."""
    return [pid for pid, meta in PLUGINS.items()
            if ANY in meta["hives"] or kind in meta["hives"]]
