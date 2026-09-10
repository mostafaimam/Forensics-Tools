r"""windows_defender - Microsoft Defender forensics.

Pulls a single detection timeline out of the four places Defender keeps
evidence:

* the ``MPLog-*.log`` scan / real-time-protection activity logs
  (``%ProgramData%\Microsoft\Windows Defender\Support``);
* the ``Microsoft-Windows-Windows Defender/Operational`` event log
  (detections 1116 / 1117, actions 1006-1009, tamper 5001 / 5007 / 5010);
* the ``Quarantine`` store - the RC4-obfuscated ``Entries`` records give
  the threat name, original path and time; ``--extract`` unwraps the
  stored file from ``ResourceData``;
* the ``SOFTWARE`` hive - scan / path / extension / process exclusions
  and the real-time-protection / tamper-protection switches.

Read-only. The RC4 key used for the quarantine store is a fixed, publicly
documented obfuscation key - nothing is cracked and no password is
required.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
