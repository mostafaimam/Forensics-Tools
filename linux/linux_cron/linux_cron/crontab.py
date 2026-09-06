"""Parse crontab-format files (system, per-user, cron.d, anacrontab)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from linux_cron.cronexpr import CronError, parse as parse_expr

_ENV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_SHORTCUT_RE = re.compile(r"^\s*(@\w+)\s+(.*\S)\s*$")


@dataclass
class CronEntry:
    schedule_raw: str
    command: str
    run_as: str = ""
    env: dict = field(default_factory=dict)
    line_no: int = 0
    parse_error: str = ""
    description: str = ""
    reboot: bool = False


def _split_5(rest: str) -> tuple[str, str] | None:
    """Split a line into (5-field schedule, remainder) or None."""
    toks = rest.split(None, 5)
    if len(toks) < 6:
        return None
    return " ".join(toks[:5]), toks[5]


def parse(text: str, with_user: bool, *, is_anacron: bool = False):
    """Yield :class:`CronEntry` for each schedule line.

    *with_user*: files in ``/etc/cron.d`` and ``/etc/crontab`` carry a user
    field between the schedule and the command; per-user spool crontabs do not.
    """
    env: dict[str, str] = {}
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENV_RE.match(line)
        if m:
            val = m.group(2)
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            env[m.group(1)] = val
            continue

        if is_anacron:
            toks = stripped.split(None, 3)
            if len(toks) < 4:
                yield CronEntry("", stripped, line_no=i, env=dict(env),
                                parse_error="anacrontab line needs 4 fields")
                continue
            period, delay, job_id, cmd = toks
            ent = CronEntry(f"@period {period} delay {delay}", cmd,
                            run_as="root", env=dict(env), line_no=i)
            ent.description = (f"every {period} day(s), {delay} min after anacron "
                               f"starts (job {job_id})")
            yield ent
            continue

        sc = _SHORTCUT_RE.match(line)
        if sc:
            sched, remainder = sc.group(1), sc.group(2)
            user, cmd = _peel_user(remainder, with_user)
        else:
            split = _split_5(stripped)
            if split is None:
                yield CronEntry("", stripped, line_no=i, env=dict(env),
                                parse_error="fewer than 6 whitespace fields")
                continue
            sched, remainder = split
            user, cmd = _peel_user(remainder, with_user)

        ent = CronEntry(sched, cmd, run_as=user, env=dict(env), line_no=i)
        try:
            s = parse_expr(sched)
            ent.description = s.describe()
            ent.reboot = s.reboot
        except CronError as e:
            ent.parse_error = str(e)
        yield ent


def _peel_user(remainder: str, with_user: bool) -> tuple[str, str]:
    if not with_user:
        return "", remainder
    parts = remainder.split(None, 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return parts[0] if parts else "", ""
