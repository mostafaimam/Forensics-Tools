"""Flatten the review into one CSV/JSON-friendly table + a text report."""

from __future__ import annotations

import io

from linux_sshkeys import flags as _flags

COLUMNS = ["kind", "user", "source", "line", "key_type", "bits", "sha256",
           "md5", "marker", "hosts", "options", "comment", "fmt", "encrypted",
           "cipher", "keyword", "value", "match", "message", "severity",
           "notable"]

_BLANK = {c: "" for c in COLUMNS}


def _key_row(k) -> dict:
    r = dict(_BLANK)
    r.update(k.row())
    r["severity"] = _flags.severity(k.notable)
    return r


def _priv_row(pk) -> dict:
    r = dict(_BLANK)
    r.update(pk.row())
    r["severity"] = _flags.severity(pk.notable)
    return r


def _finding_row(f) -> dict:
    r = dict(_BLANK)
    r.update({"kind": "config-finding", "keyword": f["keyword"],
              "value": f["value"], "match": f.get("match", ""),
              "message": f["message"], "severity": f["severity"],
              "source": f["source"], "line": f["line"] or "",
              "notable": f["message"]})
    return r


def rows(res, *, include_config_directives=False) -> list[dict]:
    out = [_key_row(k) for k in res.keys]
    out += [_priv_row(p) for p in res.private]
    out += [_finding_row(f) for f in res.config_findings]
    if include_config_directives:
        for d in res.directives:
            r = dict(_BLANK)
            r.update({"kind": "config", "keyword": d.keyword, "value": d.value,
                      "match": d.match, "source": d.source,
                      "line": d.line or ""})
            out.append(r)
    return out


def render(res) -> str:
    out = io.StringIO()
    ak = [k for k in res.keys if k.kind == "authorized_key"]
    kh = [k for k in res.keys if k.kind == "known_host"]
    hk = [k for k in res.keys if k.kind == "host_key"]

    if ak:
        out.write(f"authorized_keys ({len(ak)}):\n")
        for k in ak:
            sev = _flags.severity(k.notable)
            mark = f"  [{sev}]" if sev != "none" else ""
            out.write(f"  {k.user:<12} {k.key_type:<20} {k.sha256}"
                      f"  {k.comment}{mark}\n")
            if k.options:
                out.write(f"      options: {k.options}\n")
            for n in k.notable:
                out.write(f"      ! {n}\n")
        out.write("\n")
    if hk:
        out.write(f"host keys ({len(hk)}):\n")
        for k in hk:
            out.write(f"  {k.key_type:<20} {k.sha256}  "
                      f"{','.join(k.notable)}\n")
        out.write("\n")
    if res.private:
        out.write(f"private keys ({len(res.private)}):\n")
        for p in res.private:
            enc = p.cipher or ("encrypted" if p.encrypted else "NOT encrypted")
            out.write(f"  {p.source}  [{p.fmt}] {enc}  "
                      f"{','.join(p.notable)}\n")
        out.write("\n")
    if kh:
        out.write(f"known_hosts ({len(kh)}):\n")
        for k in kh:
            m = (k.marker + " ") if k.marker else ""
            out.write(f"  {m}{k.hosts:<40} {k.key_type:<16} "
                      f"{','.join(k.notable)}\n")
        out.write("\n")
    if res.config_findings:
        out.write(f"sshd_config review ({len(res.config_findings)}):\n")
        for f in res.config_findings:
            out.write(f"  [{f['severity']}] {f['keyword']} {f['value']}"
                      f"  - {f['message']}\n")
    return out.getvalue()
