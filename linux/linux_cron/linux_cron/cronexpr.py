"""Parse and describe a classic 5-field cron schedule."""

from __future__ import annotations

from dataclasses import dataclass

_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
           "nov", "dec"]
_DOWS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
_DOW_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
              "Saturday"]
_MONTH_NAMES = ["", "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"]

# name -> canonical "min hour dom month dow"
SHORTCUTS = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}

_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
_NAMES = [None, None, None, _MONTHS, _DOWS]


class CronError(ValueError):
    pass


@dataclass
class CronSchedule:
    raw: str
    reboot: bool = False
    # one entry per field; None means "every" (a bare *)
    minute: set | None = None
    hour: set | None = None
    dom: set | None = None
    month: set | None = None
    dow: set | None = None
    dom_restricted: bool = False
    dow_restricted: bool = False

    def describe(self) -> str:
        return describe(self)


def _parse_field(spec: str, idx: int) -> tuple[set | None, bool]:
    lo, hi = _RANGES[idx]
    names = _NAMES[idx]
    restricted = spec.strip() != "*"
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise CronError(f"empty term in field {idx + 1!r}")
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            try:
                step = int(step_s)
            except ValueError:
                raise CronError(f"bad step {step_s!r}") from None
            if step <= 0:
                raise CronError("step must be positive")
        if part in ("*", ""):
            start, end = lo, hi
        elif "-" in part:
            a, _, b = part.partition("-")
            start, end = _num(a, names, idx), _num(b, names, idx)
        else:
            start = end = _num(part, names, idx)
            if step > 1:  # "5/10" style -> from 5 to max
                end = hi
        if start > end:  # wrap, e.g. fri-mon
            seq = list(range(start, hi + 1)) + list(range(lo, end + 1))
        else:
            seq = list(range(start, end + 1))
        for i, v in enumerate(seq):
            if i % step == 0:
                out.add(v)
    if idx == 4:  # normalise Sunday 7 -> 0
        if 7 in out:
            out.discard(7)
            out.add(0)
    if not restricted:
        return None, False
    return out, restricted


def _num(tok: str, names, idx: int) -> int:
    tok = tok.strip().lower()
    if names and tok[:3] in names:
        return names.index(tok[:3]) + (1 if idx == 3 else 0)
    try:
        return int(tok)
    except ValueError:
        raise CronError(f"not a number or known name: {tok!r}") from None


def parse(spec: str) -> CronSchedule:
    """Parse a schedule string (5 fields, or an ``@`` shortcut)."""
    s = spec.strip()
    if not s:
        raise CronError("empty schedule")
    low = s.lower()
    if low == "@reboot":
        return CronSchedule(raw=s, reboot=True)
    if low in SHORTCUTS:
        s = SHORTCUTS[low]
    parts = s.split()
    if len(parts) < 5:
        raise CronError(f"expected 5 fields, got {len(parts)}: {spec!r}")
    fields = parts[:5]
    mi, _ = _parse_field(fields[0], 0)
    ho, _ = _parse_field(fields[1], 1)
    do, dor = _parse_field(fields[2], 2)
    mo, _ = _parse_field(fields[3], 3)
    dw, dwr = _parse_field(fields[4], 4)
    return CronSchedule(raw=s, minute=mi, hour=ho, dom=do, month=mo, dow=dw,
                        dom_restricted=dor, dow_restricted=dwr)


def _fmt_set(values: set | None, kind: str) -> str:
    if values is None:
        return ""
    vs = sorted(values)
    if kind == "dow":
        return ", ".join(_DOW_NAMES[v] for v in vs)
    if kind == "month":
        return ", ".join(_MONTH_NAMES[v] for v in vs)
    return ", ".join(str(v) for v in vs)


def _is_contiguous_step(values: set, lo: int, hi: int) -> int | None:
    vs = sorted(values)
    if len(vs) < 2:
        return None
    step = vs[1] - vs[0]
    if step > 1 and all(b - a == step for a, b in zip(vs, vs[1:])) and vs[0] == lo:
        return step
    return None


def _hour_span(hours: set) -> str:
    vs = sorted(hours)
    if vs == list(range(vs[0], vs[-1] + 1)) and len(vs) > 1:
        return f"between {vs[0]:02d}:00 and {vs[-1]:02d}:59"
    return "during " + ", ".join(f"{h:02d}:00" for h in vs)


def describe(c: CronSchedule) -> str:
    if c.reboot:
        return "at boot (@reboot)"
    bits = []
    min_step = (_is_contiguous_step(c.minute, 0, 59)
                if c.minute is not None else None)
    # time of day
    if c.minute is None and c.hour is None:
        bits.append("every minute")
    elif c.minute is None and c.hour is not None:
        bits.append(f"every minute {_hour_span(c.hour)}")
    elif min_step and c.hour is None:
        bits.append(f"every {min_step} minutes")
    elif min_step and c.hour is not None:
        bits.append(f"every {min_step} minutes {_hour_span(c.hour)}")
    elif c.hour is None:
        if len(c.minute) == 1:
            bits.append(f"at :{next(iter(c.minute)):02d} past every hour")
        else:
            bits.append(f"at minutes {_fmt_set(c.minute, 'min')} past every hour")
    else:
        hr_step = _is_contiguous_step(c.hour, 0, 23)
        mins = sorted(c.minute)
        if hr_step:
            bits.append(f"every {hr_step} hours at :{mins[0]:02d}")
        elif len(c.hour) * len(mins) <= 6:
            times = ", ".join(f"{h:02d}:{m:02d}" for h in sorted(c.hour)
                              for m in mins)
            bits.append(f"at {times}")
        else:
            bits.append(f"at minutes {_fmt_set(c.minute, 'min')} "
                        f"{_hour_span(c.hour)}")
    # day
    day_bits = []
    if c.dom_restricted:
        day_bits.append(f"on day-of-month {_fmt_set(c.dom, 'dom')}")
    if c.dow_restricted:
        day_bits.append(f"on {_fmt_set(c.dow, 'dow')}")
    if day_bits:
        # cron OR-s dom and dow when both are restricted
        bits.append(" or ".join(day_bits))
    if c.month is not None:
        bits.append(f"in {_fmt_set(c.month, 'month')}")
    return ", ".join(bits)
