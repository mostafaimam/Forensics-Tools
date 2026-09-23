from __future__ import annotations

import pytest

from suite_console.discovery import discover_tools, find_repo_root


def test_find_repo_root_locates_real_repo():
    root = find_repo_root()
    assert (root / "shared").is_dir()
    assert (root / "windows").is_dir()
    assert (root / "memory").is_dir()


def test_discover_tools_finds_142_or_more():
    tools = discover_tools()
    # >= rather than == : this suite grows over time, and the launcher
    # should never need updating when it does
    assert len(tools) >= 142


def test_discover_tools_excludes_shared_and_suite():
    tools = discover_tools()
    categories = {t.category for t in tools}
    assert "shared" not in categories
    assert "suite" not in categories


def test_discover_tools_finds_known_tool_with_description():
    tools = discover_tools()
    by_name = {t.name: t for t in tools}
    assert "memory_timers" in by_name
    t = by_name["memory_timers"]
    assert t.category == "memory"
    assert t.description
    assert t.package_dir.name == "memory_timers"
    assert (t.package_dir / "cli.py").exists()


def test_discover_tools_detects_gui_presence():
    tools = discover_tools()
    by_name = {t.name: t for t in tools}
    assert by_name["memory_timers"].has_gui


def test_discover_tools_every_entry_has_a_cli():
    for t in discover_tools():
        assert (t.package_dir / "cli.py").exists(), t.name


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
