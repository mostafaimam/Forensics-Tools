"""windows_tasks - Scheduled Tasks from the Tasks XML + TaskCache registry.

Correlates the on-disk task definitions in
``C:\\Windows\\System32\\Tasks\\**`` with the
``SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache``
registry keys into one row per task:

* from the XML - author, registration date, description, the triggers
  (rendered in plain language), the principal (run-as SID, run level,
  logon type), the hidden / enabled flags, and every action (``Exec``
  command + arguments + working directory, or a ``ComHandler`` CLSID);
* from ``TaskCache\\Tasks\\{GUID}`` - the ``DynamicInfo`` timestamps
  (task registered, last run) and the security descriptor;
* from ``TaskCache\\Tree`` - whether the task is present in the tree
  (a GUID under ``Tasks`` with no ``Tree`` entry is a classic hiding
  trick) and the tree key's last-written time.

Flags living-off-the-land binaries, user-writable / UNC action paths,
encoded PowerShell, hidden tasks, tasks registered outside
``\\Microsoft\\Windows``, SYSTEM tasks that run a user-path binary,
``ComHandler`` actions and registry-only / orphaned tasks.  Pure standard
library (the ``regf`` hive parser is vendored).
"""

__version__ = "0.1.0"
