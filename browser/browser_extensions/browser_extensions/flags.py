"""Risk heuristics for an extension."""

from __future__ import annotations

from browser_extensions import permissions as _perm

_SIDELOAD_SOURCES = {
    "sideload-registry", "sideload-pref", "sideload-pref-download",
    "command-line", "unpacked", "temporary/unpacked",
}
_POLICY_SOURCES = {"policy", "policy-component"}

# Google / Mozilla first-party component & default extensions.  Chrome ships
# these via the "external pref download" path, which otherwise looks like a
# sideload - so treat these ids as trusted.
_FIRST_PARTY = {
    "nmmhkkegccagdldgiimedpiccmgmieda",  # Chrome Web Store Payments
    "mhjfbmdgcfjbbpaeojofohoefgiehjai",  # Chrome PDF Viewer
    "nkeimhogjdpnpccoofpliimaahmaaome",  # Google Hangouts
    "neajdppkdcdipfabeoofebfddakdcjhd",  # Google Network Speech
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",  # Google Docs Offline
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm",  # Media Router / Cast
    "ahfgeienlihckogmohjhadlkjgocpleb",  # Chrome Web Store
    "aapocclcgogkmnckokdopfmhonfmgoek",  # Google Slides
    "aohghmighlieiainnegkcijnfilokake",  # Google Docs
    "apdfllckaahabafndbhieahigkjlhalf",  # Google Drive
    "felcaaldnbdncclmpmpeirstmbjbihnh",  # Google Sheets
    "blpcfgokakmgnkcojhhkbfbldkacnbeo",  # YouTube
    "pjkljhegncpnkpknbcohdijeoejaedia",  # Gmail
    "coobgpohoikkiipiblmjeljniedjpjpf",  # Google Search
    "internal-remotedesktop",
    "screenshot@mozilla.org", "google@search.mozilla.org",
    "amazondotcom@search.mozilla.org", "wikipedia@search.mozilla.org",
    "ddg@search.mozilla.org", "bing@search.mozilla.org",
    "formautofill@mozilla.org", "pictureinpicture@mozilla.org",
    "webcompat@mozilla.org", "default-theme@mozilla.org",
}


def flag(ext) -> tuple[list[str], str]:
    notable: list[str] = []
    api = ext.api_permissions
    hosts = ext.host_permissions
    first_party = ext.ext_id in _FIRST_PARTY

    perm_score, reasons = _perm.score(api, hosts)
    for r in reasons:
        notable.append(r.split(":")[0] if ":" in r else r)

    src = (ext.install_source or "").lower()
    upd = (ext.update_url or "").lower()
    google_upd = ("clients2.google.com" in upd or "google.com/service/update"
                  in upd or not upd)
    # location 5 (external-pref-download) with a Google update endpoint is how
    # Chrome ships its own bundled components - not a third-party sideload
    if first_party or (src == "sideload-pref-download" and google_upd
                       and not ext.from_webstore):
        return [], "low"
    if src in _SIDELOAD_SOURCES:
        notable.append(f"sideloaded ({src})")
    elif src in _POLICY_SOURCES:
        notable.append("installed by policy")
    elif "unpacked" in src or "temporary" in src:
        notable.append("developer / unpacked")
    elif src in ("", "unknown", "invalid"):
        notable.append("unknown install source")

    if ext.browser.lower().startswith("firefox"):
        if ext.signed_state in ("unsigned", "unknown", "broken"):
            notable.append(f"{ext.signed_state} add-on")
    else:
        if not ext.from_webstore and src not in ("webstore", "component",
                                                 "builtin", "system",
                                                 "external-component"):
            notable.append("not from the web store")

    if ext.update_url and "google.com" not in ext.update_url \
            and "mozilla.org" not in ext.update_url \
            and "clients2.google.com" not in ext.update_url:
        notable.append("custom update URL")

    if ext.background == "persistent":
        notable.append("persistent background page")

    if not ext.enabled and ext.disabled_reason and "user" not in \
            ext.disabled_reason:
        notable.append(f"disabled: {ext.disabled_reason}")

    # dedupe, keep order
    seen = set()
    notable = [n for n in notable if not (n in seen or seen.add(n))]

    trusted_source = (
        src in ("webstore", "component", "builtin", "system",
                "external-component", "policy", "policy-component")
        or ext.from_webstore
        or (ext.browser.lower().startswith("firefox")
            and ext.signed_state in ("signed", "system")))
    off_store = any(n.startswith("sideloaded") or "unsigned add-on" in n
                    or "developer / unpacked" in n
                    or "unknown install source" in n for n in notable)
    dangerous_api = bool({"debugger", "nativeMessaging", "management",
                          "proxy"} & set(api))

    risk = "low"
    if off_store and (perm_score >= 2 or dangerous_api or notable):
        risk = "high"
    elif dangerous_api and not trusted_source:
        risk = "high"
    elif perm_score >= 3 and not trusted_source:
        risk = "high"
    elif perm_score >= 2 or (notable and not (
            len(notable) == 1 and notable[0] == "host access")):
        risk = "medium"
    elif notable:
        risk = "medium"
    return notable, risk
