"""Read Defender exclusions and protection switches from the SOFTWARE hive."""

from __future__ import annotations

from dataclasses import dataclass

from windows_defender.hive import HiveError, RegistryHive, to_text

_BASES = (
    "Microsoft\\Windows Defender",
    "Policies\\Microsoft\\Windows Defender",
    "WOW6432Node\\Microsoft\\Windows Defender",
)
_EXCL = ("Exclusions\\Paths", "Exclusions\\Extensions",
         "Exclusions\\Processes", "Exclusions\\IpAddresses",
         "Exclusions\\TemporaryPaths")
_SWITCHES = {
    "DisableAntiSpyware": ("anti-spyware disabled", "Windows Defender"),
    "DisableAntiVirus": ("anti-virus disabled", "Windows Defender"),
    "DisableRealtimeMonitoring": ("real-time monitoring disabled",
                                  "Real-Time Protection"),
    "DisableBehaviorMonitoring": ("behaviour monitoring disabled",
                                  "Real-Time Protection"),
    "DisableOnAccessProtection": ("on-access protection disabled",
                                  "Real-Time Protection"),
    "DisableScanOnRealtimeEnable": ("scan-on-enable disabled",
                                    "Real-Time Protection"),
    "DisableIOAVProtection": ("downloaded-file scanning disabled",
                              "Real-Time Protection"),
    "DisableBlockAtFirstSeen": ("block-at-first-sight disabled",
                                "Spynet"),
    "SpynetReporting": ("MAPS reporting level", "Spynet"),
    "SubmitSamplesConsent": ("sample submission consent", "Spynet"),
    "PUAProtection": ("PUA protection level", "Windows Defender"),
    "TamperProtection": ("tamper protection state", "Features"),
    "DisableRoutinelyTakingAction": ("automatic action disabled",
                                     "Windows Defender"),
}


@dataclass
class CfgRow:
    kind: str
    time: str
    path: str
    detail: str
    source: str

    def row(self) -> dict:
        return {"kind": self.kind, "time": self.time, "path": self.path,
                "detail": self.detail, "source": self.source}


def _get(hive: RegistryHive, *cands):
    for c in cands:
        k = hive.get(c)
        if k is not None:
            return k
    return None


def _lw(key) -> str:
    v = getattr(key, "last_written", "") or ""
    if hasattr(v, "strftime"):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(v)


def parse_software_hive(data: bytes, source: str) -> list[CfgRow]:
    rows: list[CfgRow] = []
    try:
        hive = RegistryHive(data)
    except HiveError:
        return rows

    for base in _BASES:
        for sub in _EXCL:
            k = _get(hive, f"{base}\\{sub}")
            if k is None:
                continue
            lw = _lw(k)
            cat = sub.split("\\")[-1].lower()
            for v in k.values():
                name = v.name or "(default)"
                rows.append(CfgRow(
                    kind=f"exclusion-{cat}", time=lw, path=name,
                    detail=f"{base}\\{sub}", source=source))

        for vname, (desc, subkey) in _SWITCHES.items():
            seen = False
            for cand in dict.fromkeys((f"{base}\\{subkey}", base)):
                if seen:
                    break
                k = hive.get(cand)
                if k is None:
                    continue
                for v in k.values():
                    if (v.name or "").lower() != vname.lower():
                        continue
                    val = to_text(v.data)
                    rows.append(CfgRow(
                        kind="protection-setting", time=_lw(k),
                        path=f"{vname} = {val}",
                        detail=f"{desc} ({cand})", source=source))
                    seen = True
    return rows
