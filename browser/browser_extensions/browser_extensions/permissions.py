"""Risk weighting for extension permissions."""

from __future__ import annotations

# API permission -> (risk 1..3, why)
API_RISK = {
    "debugger": (3, "attach the DevTools debugger to any page"),
    "nativeMessaging": (3, "talk to a native host binary on disk"),
    "proxy": (3, "reroute all traffic through a proxy"),
    "webRequestBlocking": (3, "intercept and modify every request"),
    "declarativeNetRequestWithHostAccess": (3, "rewrite requests"),
    "management": (3, "install / remove / disable other extensions"),
    "privacy": (2, "change privacy settings"),
    "webRequest": (2, "observe every request"),
    "cookies": (2, "read cookies for its host permissions"),
    "history": (2, "read and delete browsing history"),
    "downloads": (2, "start downloads and open files"),
    "tabs": (2, "see URLs / titles of every tab"),
    "scripting": (2, "inject scripts into pages"),
    "clipboardRead": (2, "read the clipboard"),
    "bookmarks": (1, "read and change bookmarks"),
    "geolocation": (1, "read the device location"),
    "browsingData": (2, "clear browsing data"),
    "declarativeNetRequest": (1, "block / redirect requests by rule"),
    "contentSettings": (2, "change site content settings"),
    "identity": (1, "get an OAuth token for the signed-in account"),
    "unlimitedStorage": (1, "unbounded local storage"),
    "clipboardWrite": (1, "write to the clipboard"),
    "storage": (0, ""),
    "alarms": (0, ""),
    "notifications": (0, ""),
    "contextMenus": (0, ""),
}

BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*",
               "*://*/", "file:///*", "<all_urls>")


def host_breadth(hosts: list[str]) -> int:
    """0 = none, 1 = a few sites, 2 = a whole scheme, 3 = everything."""
    if not hosts:
        return 0
    for h in hosts:
        if h in ("<all_urls>", "*://*/*"):
            return 3
    for h in hosts:
        if h in ("http://*/*", "https://*/*") or h.startswith("*://*."):
            return 2
    return 1


def score(api: list[str], hosts: list[str]) -> tuple[int, list[str]]:
    reasons: list[str] = []
    top = 0
    for p in api:
        r, why = API_RISK.get(p, (0, ""))
        if r >= 2 and why:
            reasons.append(f"{p}: {why}")
        top = max(top, r)
    hb = host_breadth(hosts)
    if hb == 3:
        reasons.append("host access: every site")
        top = max(top, 2)
    elif hb == 2:
        reasons.append("host access: a whole scheme")
        top = max(top, 2)
    # webRequest + broad host access = can silently read/modify all traffic
    if ("webRequest" in api or "webRequestBlocking" in api) and hb >= 2:
        reasons.append("can read/modify traffic on every site")
        top = 3
    return top, reasons
