"""Parse systemd ``.timer`` units (and the ``.service`` they trigger)."""

from __future__ import annotations

from dataclasses import dataclass


def parse_unit(text: str) -> dict[str, dict[str, list[str]]]:
    """systemd unit -> {section: {key: [values...]}}.

    Duplicate keys accumulate; a bare ``Key=`` resets that key to empty.
    Continuation lines (trailing ``\\``) are joined.
    """
    out: dict[str, dict[str, list[str]]] = {}
    section = None
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if pending:
            line = pending + " " + line
            pending = ""
        if line.endswith("\\"):
            pending = line[:-1].rstrip()
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            out.setdefault(section, {})
            continue
        if section is None or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        bucket = out[section].setdefault(key, [])
        if val == "":
            bucket.clear()
        else:
            bucket.append(val)
    return out


@dataclass
class TimerJob:
    timer_unit: str
    triggers_unit: str = ""
    schedule_raw: str = ""
    description: str = ""
    command: str = ""
    run_as: str = ""
    persistent: bool = False
    enabled: str = ""          # "enabled" / "disabled" / "" (unknown)
    timer_file: str = ""
    service_file: str = ""
    parse_error: str = ""


_TIMER_KEYS = ["OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec",
               "OnUnitInactiveSec", "OnActiveSec"]


def _describe(timer: dict[str, list[str]]) -> tuple[str, str]:
    parts = []
    for k in _TIMER_KEYS:
        for v in timer.get(k, []):
            parts.append(f"{k}={v}")
    raw = "; ".join(parts)
    human = []
    for v in timer.get("OnCalendar", []):
        human.append(_describe_calendar(v))
    for k in ("OnBootSec", "OnStartupSec"):
        for v in timer.get(k, []):
            human.append(f"{v} after {'boot' if 'Boot' in k else 'systemd start'}")
    for v in timer.get("OnUnitActiveSec", []):
        human.append(f"every {v} after the service last activated")
    return raw, "; ".join(human) if human else raw


_CAL_WORDS = {
    "minutely": "every minute", "hourly": "every hour", "daily": "every day",
    "weekly": "Mondays 00:00", "monthly": "1st of the month 00:00",
    "yearly": "Jan 1 00:00", "annually": "Jan 1 00:00", "quarterly": "quarterly",
    "semiannually": "twice a year",
}


def _describe_calendar(expr: str) -> str:
    e = expr.strip().lower()
    if e in _CAL_WORDS:
        return _CAL_WORDS[e]
    return f"OnCalendar {expr}"


def build_timer_job(timer_text: str, timer_name: str,
                    resolve_service) -> TimerJob:
    """*resolve_service(unit_name)* -> (service_text, service_path) or (None, "")."""
    job = TimerJob(timer_unit=timer_name, timer_file="")
    try:
        u = parse_unit(timer_text)
    except Exception as e:  # noqa: BLE001
        job.parse_error = f"timer parse: {e}"
        return job
    timer_sec = u.get("Timer", {})
    unit_sec = u.get("Unit", {})
    job.description = (unit_sec.get("Description", [""]) or [""])[0]
    job.persistent = (timer_sec.get("Persistent", ["no"])[-1].lower()
                      in ("1", "yes", "true", "on"))
    job.schedule_raw, human = _describe(timer_sec)
    if human:
        job.description = (job.description + " -- " if job.description else "") + human

    target = (timer_sec.get("Unit", [""])[-1]
              or timer_name.rsplit(".", 1)[0] + ".service")
    job.triggers_unit = target
    svc_text, svc_path = resolve_service(target)
    if svc_text is not None:
        job.service_file = svc_path
        try:
            s = parse_unit(svc_text)
            svc = s.get("Service", {})
            execs = (svc.get("ExecStart", []) or svc.get("ExecStartPre", []))
            job.command = " && ".join(execs)
            job.run_as = (svc.get("User", [""]) or [""])[-1] or "root"
        except Exception as e:  # noqa: BLE001
            job.parse_error = f"service parse: {e}"
    else:
        job.run_as = "root"
    return job
