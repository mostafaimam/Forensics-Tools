r"""macos_quarantine - LaunchServices quarantine events (download provenance).

Reads ``com.apple.LaunchServices.QuarantineEventsV2`` (a SQLite database
under ``~/Library/Preferences/``) - the "downloaded from the internet"
store that drives Gatekeeper's *"are you sure you want to open this"*
prompt.

Per event: the quarantine identifier, the timestamp (Mac absolute time
-> UTC), the agent that downloaded the file (bundle id + name, e.g.
``com.apple.Safari`` / ``Safari``), the **data URL** (the file that was
downloaded), the **origin URL** (the page it came from), the sender
name / address (for email attachments) and the event type.

Flags executables / disk images / scripts / archives fetched from the
internet, downloads from IP-literal or punycode hosts, and downloads via
``curl`` / ``wget`` / a scripting agent.  Pure standard library,
read-only.
"""

__version__ = "0.1.0"
