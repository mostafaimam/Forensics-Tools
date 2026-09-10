r"""windows_wmi - WMI repository persistence forensics.

Scans the WMI CIM repository (``OBJECTS.DATA``, with ``MAPPING*.MAP`` used
to prefer live pages) for the event-subscription persistence triad:

* ``__EventFilter``            - the WQL trigger query
* ``*EventConsumer``           - the action: a command line
  (``CommandLineEventConsumer``), a script
  (``ActiveScriptEventConsumer``), a log write, an SMTP mail, ...
* ``__FilterToConsumerBinding`` - the link that arms a filter/consumer pair

This is a classic fileless persistence mechanism (an ``__EventFilter`` on
``Win32_Process`` creation bound to a PowerShell ``CommandLineEventConsumer``
survives reboots and leaves nothing on disk but the repository).  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
