"""browser_extensions - installed browser extensions from a disk image.

Reads the Chromium family (``Preferences`` / ``Secure Preferences``) and
Firefox (``extensions.json``) and lists every extension: id, name,
version, install source, enabled state, and the **host and API
permissions** it holds.

Extensions installed **outside the web store** (sideloaded, unpacked /
developer mode, external registry / policy), **unsigned** Firefox
add-ons, and extensions holding high-risk permissions - `<all_urls>` +
`webRequest`, `nativeMessaging`, `debugger`, `proxy`, `cookies`,
`management` - are flagged.  Malicious extensions are a common,
low-noise persistence and data-theft vector.
"""

__version__ = "0.1.0"
