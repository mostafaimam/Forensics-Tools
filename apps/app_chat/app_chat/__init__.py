r"""app_chat - chat/collaboration app forensics, one adapter per app.

Most desktop chat clients (Slack, Discord, classic Microsoft Teams) are
Electron apps and cache data the same way any Chromium app does: in a
Local Storage / IndexedDB LevelDB directory. This vendors the same
from-scratch LevelDB reader `browser_localstorage` built (WAL log +
SSTable + Snappy decompression) and layers per-app recognition on top.

For Slack and Discord, message objects are recognized by their
**documented public Web API JSON shape** (Slack's ``type: "message"``
events, Discord's message object) wherever they turn up in a cached
LevelDB value - a real, published format, not a guess at the client's
internal storage schema. Classic Teams data is located and its LevelDB
values are carved for embedded JSON/text, without claiming to decode a
specific message schema (less confidently documented than Slack's or
Discord's own API).

**Signal Desktop, WhatsApp Desktop, and Telegram Desktop are out of
scope for v0.1** - Signal's database needs a key from the app's own
``config.json`` this project has no verified way to apply, WhatsApp
Desktop's local storage format isn't confidently known, and Telegram's
``tdata`` is itself encrypted by the account passcode. See the README.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
