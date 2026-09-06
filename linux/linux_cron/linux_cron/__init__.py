"""linux_cron - scheduled-execution inventory for Linux systems.

Collects and normalises every place a Linux host can schedule a command:
system and user crontabs, ``/etc/cron.d``, the ``cron.{hourly,daily,weekly,
monthly}`` run-parts directories, ``/etc/anacrontab``, ``at`` spool jobs and
systemd timer units.  One row per scheduled job, with a plain-language
description of when it runs and a heuristic flag for suspicious entries.
"""

__version__ = "0.1.0"
