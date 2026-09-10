"""Build a synthetic OBJECTS.DATA with an event-subscription triad."""

from __future__ import annotations

PAD = b"\xab" * 300


def _rec(marker: str, strings: list[str]) -> bytes:
    out = bytearray(PAD)
    out += marker.encode("latin-1") + b"\x00"
    for s in strings:
        out += b"\x00\x00" + s.encode("latin-1") + b"\x00\x00"
    out += PAD
    return bytes(out)


NS = "\\\\.\\root\\subscription"
NS_ODD = "\\\\.\\root\\CustomNS"

PS_CMD = ("powershell.exe -NoProfile -w hidden -enc "
          "SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA")
VBS = ("Set objShell = CreateObject(\"WScript.Shell\") : "
       "objShell.Run \"powershell -nop -c IEX(...)\"")
WQL = ("SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE "
       "TargetInstance ISA 'Win32_Process'")


def build_objects() -> bytes:
    blob = bytearray()
    blob += _rec("__EventFilter", ["SecurityUpdaterFilter", NS, WQL])
    blob += _rec("CommandLineEventConsumer",
                 ["SecurityUpdaterConsumer", NS, PS_CMD])
    blob += _rec("__FilterToConsumerBinding", [
        NS + ':__EventFilter.Name="SecurityUpdaterFilter"',
        NS + ':CommandLineEventConsumer.Name="SecurityUpdaterConsumer"',
        NS])
    # a second, script-based consumer in an odd namespace
    blob += _rec("ActiveScriptEventConsumer",
                 ["ScriptConsumer", NS_ODD, VBS])
    # a benign log consumer
    blob += _rec("LogFileEventConsumer",
                 ["AuditLogger", NS, "C:\\logs\\wmi-audit.log"])
    return bytes(blob)
